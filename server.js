import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error('Missing DATABASE_URL, JWT_SECRET, ADMIN_EMAIL or ADMIN_PASSWORD');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});
// Render terminates TLS at its proxy; trust the single platform proxy so
// rate limiting can identify clients correctly from X-Forwarded-For.
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '20kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }));
app.use('/api/withdrawals', rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }));

await pool.query(`
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY,
 email TEXT UNIQUE,
 phone TEXT UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
 status TEXT NOT NULL DEFAULT 'pending_verification',
 balance_kobo BIGINT NOT NULL DEFAULT 0 CHECK (balance_kobo >= 0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS withdrawals (
 id BIGSERIAL PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES users(id),
 reference TEXT NOT NULL UNIQUE,
 amount_kobo BIGINT NOT NULL CHECK (amount_kobo > 0),
 bank_name TEXT NOT NULL,
 account_name TEXT NOT NULL,
 account_number TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','paid','rejected')),
 admin_note TEXT,
 reviewed_by BIGINT REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS wallet_ledger (
 id BIGSERIAL PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES users(id),
 type TEXT NOT NULL,
 amount_kobo BIGINT NOT NULL,
 reference TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS withdrawals_status_created_idx ON withdrawals(status, created_at DESC);
ALTER TABLE users ADD COLUMN IF NOT EXISTS date_of_birth DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_reviewed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_note TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS country TEXT NOT NULL DEFAULT 'NG';
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS password_reset_tokens (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,token_hash TEXT NOT NULL UNIQUE,expires_at TIMESTAMPTZ NOT NULL,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS password_reset_user_idx ON password_reset_tokens(user_id,created_at DESC);

CREATE TABLE IF NOT EXISTS virtual_matches (
 id BIGSERIAL PRIMARY KEY,
 match_code TEXT NOT NULL UNIQUE,
 sport TEXT NOT NULL CHECK (sport IN ('football','basketball','tennis','racing')),
 league TEXT NOT NULL,
 home TEXT NOT NULL,
 away TEXT NOT NULL,
 participants JSONB NOT NULL DEFAULT '[]'::jsonb,
 status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled','live','completed')),
 duration_seconds INTEGER NOT NULL,
 scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 started_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 home_score INTEGER,
 away_score INTEGER,
 result JSONB NOT NULL DEFAULT '{}'::jsonb,
 events JSONB NOT NULL DEFAULT '[]'::jsonb,
 seed_hash TEXT NOT NULL,
 seed_secret TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS virtual_matches_sport_status_idx ON virtual_matches(sport,status,scheduled_at);
CREATE INDEX IF NOT EXISTS virtual_matches_completed_idx ON virtual_matches(completed_at DESC);

CREATE TABLE IF NOT EXISTS betslip_codes (
 code CHAR(5) PRIMARY KEY,
 selections JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
);
CREATE INDEX IF NOT EXISTS betslip_codes_expiry_idx ON betslip_codes(expires_at);

`);

const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
const existingAdmin = await pool.query('SELECT id FROM users WHERE lower(email)=lower($1)', [ADMIN_EMAIL]);
if (!existingAdmin.rowCount) {
  await pool.query("INSERT INTO users(email,password_hash,role,status) VALUES($1,$2,'admin','active')", [ADMIN_EMAIL, adminHash]);
} else {
  await pool.query("UPDATE users SET role='admin',status='active',password_hash=$2 WHERE id=$1", [existingAdmin.rows[0].id, adminHash]);
}

function tokenFor(user) {
 return jwt.sign({ sub: String(user.id), role: user.role }, JWT_SECRET, { expiresIn: '30d', issuer: 'sooty-bet' });
}
function auth(req,res,next) {
 const raw = req.headers.authorization || '';
 try {
  const payload = jwt.verify(raw.replace(/^Bearer\s+/i,''), JWT_SECRET, { issuer: 'sooty-bet' });
  req.auth = payload; next();
 } catch { res.status(401).json({ error: 'Please sign in again.' }); }
}
function adminOnly(req,res,next) {
 if (req.auth?.role !== 'admin') return res.status(403).json({ error: 'Admin access only.' });
 next();
}
function cleanText(v,max=100) { return typeof v === 'string' ? v.trim().slice(0,max) : ''; }
function ref() { return 'SWD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,7).toUpperCase(); }


// Free football fixtures from TheSportsDB. Its free tier does not include live scores.
const sportsCache = new Map();
async function sportsDay(date) {
  const key = 'day:' + date;
  const cached = sportsCache.get(key);
  if (cached && Date.now() - cached.at < 10 * 60 * 1000) return cached.data;
  const url = 'https://www.thesportsdb.com/api/v1/json/123/eventsday.php?d=' + encodeURIComponent(date) + '&s=Soccer';
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  if (!response.ok) {
    const error = new Error('The free sports fixtures service is temporarily unavailable.');
    error.status = 502;
    throw error;
  }
  const body = await response.json().catch(() => ({}));
  const data = (body.events || []).map(item => ({
    id: item.idEvent,
    league: item.strLeague || 'Football',
    country: item.strCountry || '',
    home: item.strHomeTeam || 'Home',
    away: item.strAwayTeam || 'Away',
    homeScore: item.intHomeScore == null ? null : Number(item.intHomeScore),
    awayScore: item.intAwayScore == null ? null : Number(item.intAwayScore),
    status: 'NS',
    statusText: 'Scheduled fixture',
    elapsed: null,
    kickoff: item.strTimestamp || (item.dateEvent && item.strTime ? item.dateEvent + 'T' + item.strTime + 'Z' : item.dateEvent || null),
    venue: item.strVenue || ''
  })).filter(item => item.home && item.away);
  sportsCache.set(key, { at: Date.now(), data });
  return data;
}
function dateOffset(days) {
  const date = new Date();
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}
app.post('/api/betslip-codes', async (req,res) => {
 try {
  const incoming=Array.isArray(req.body?.selections)?req.body.selections:[];
  if(!incoming.length||incoming.length>20) return res.status(400).json({error:'A betslip must contain between 1 and 20 selections.'});
  const selections=incoming.map(x=>({
   id:cleanText(String(x.id??''),80),
   home:cleanText(x.home,120),away:cleanText(x.away,120),
   pick:cleanText(x.pick,80),pickLabel:cleanText(x.pickLabel,120),
   market:cleanText(x.market,100),odd:Number(x.odd),
   isVirtual:Boolean(x.isVirtual),matchId:Number.isSafeInteger(Number(x.matchId))?Number(x.matchId):null
  }));
  if(selections.some(x=>!x.home||!x.pick||!Number.isFinite(x.odd)||x.odd<=1||x.odd>10000))
   return res.status(400).json({error:'One or more selections are invalid. Please refresh your betslip.'});
  const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for(let attempt=0;attempt<8;attempt++){
   const bytes=crypto.randomBytes(5);
   const code=Array.from(bytes,b=>alphabet[b%alphabet.length]).join('');
   try {
    await pool.query('INSERT INTO betslip_codes(code,selections) VALUES($1,$2)',[code,JSON.stringify(selections)]);
    return res.status(201).json({code,expiresInDays:30});
   } catch(e) { if(e.code!=='23505') throw e; }
  }
  return res.status(503).json({error:'Could not create a load code. Please try again.'});
 } catch(e) { console.error('Betslip code creation failed:',e.message);res.status(500).json({error:'Could not create a betslip load code.'}); }
});
app.get('/api/betslip-codes/:code',async(req,res)=>{
 const code=cleanText(req.params.code,5).toUpperCase();
 if(!/^[A-HJ-NP-Z2-9]{5}$/.test(code)) return res.status(400).json({error:'Enter a valid 5-character betslip code.'});
 try {
  const result=await pool.query('SELECT selections FROM betslip_codes WHERE code=$1 AND expires_at>NOW()',[code]);
  if(!result.rowCount) return res.status(404).json({error:'Betslip code not found or expired.'});
  res.set('Cache-Control','no-store');
  res.json({code,selections:result.rows[0].selections});
 } catch(e) { console.error('Betslip code lookup failed:',e.message);res.status(500).json({error:'Could not load that betslip right now.'}); }
});

// Live and scheduled football data. Set API_FOOTBALL_KEY in Render to enable
// the licensed API-Sports feed; never expose this key to the browser.
const API_FOOTBALL_KEY = process.env.API_FOOTBALL_KEY || '';
const footballCache = new Map();
async function apiFootball(path, params = {}) {
  if (!API_FOOTBALL_KEY) return null;
  const url = new URL('https://v3.football.api-sports.io/' + path);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
  const response = await fetch(url, { headers: { 'x-apisports-key': API_FOOTBALL_KEY, accept: 'application/json' } });
  if (!response.ok) throw new Error('Live football provider returned HTTP ' + response.status);
  const body = await response.json();
  if (body.errors && Object.keys(body.errors).length) throw new Error('Football provider rejected the request: ' + JSON.stringify(body.errors));
  return body.response || [];
}
function mapApiFootballFixture(row) {
  const f = row.fixture || {}, league = row.league || {}, teams = row.teams || {}, goals = row.goals || {};
  const status = f.status || {};
  return {
    id: String(f.id), providerId: Number(f.id), league: league.name || 'Football',
    country: league.country || '', home: teams.home?.name || 'Home', away: teams.away?.name || 'Away',
    homeScore: goals.home == null ? null : Number(goals.home), awayScore: goals.away == null ? null : Number(goals.away),
    status: status.short || 'NS', statusText: status.long || 'Scheduled',
    elapsed: status.elapsed == null ? null : Number(status.elapsed),
    kickoff: f.date || null, venue: f.venue?.name || '',
    live: ['1H','HT','2H','ET','P','LIVE'].includes(status.short),
    source: 'API-Football'
  };
}
async function footballFixtureFeed(kind) {
  const cacheKey = 'football:' + kind, cached = footballCache.get(cacheKey);
  const ttl = kind === 'live' ? 15000 : 180000;
  if (cached && Date.now() - cached.at < ttl) return cached.data;
  if (!API_FOOTBALL_KEY) return null;
  const rows = kind === 'live'
    ? await apiFootball('fixtures', { live: 'all', timezone: 'Africa/Lagos' })
    : await apiFootball('fixtures', { from: dateOffset(0), to: dateOffset(7), timezone: 'Africa/Lagos' });
  const data = rows.map(mapApiFootballFixture);
  footballCache.set(cacheKey, { at: Date.now(), data });
  return data;
}
app.get('/api/sports/live', async (_req, res) => {
  try {
    const matches = await footballFixtureFeed('live');
    res.set('Cache-Control', 'no-store');
    if (matches) return res.json({ matches, updatedAt: new Date().toISOString(), provider: 'API-Football' });
    return res.json({ matches: [], updatedAt: new Date().toISOString(), provider: 'Not configured', message: 'Add API_FOOTBALL_KEY to the backend service to enable verified live scores.' });
  } catch (e) {
    res.status(502).json({ error: e.message || 'Could not load live fixtures.' });
  }
});
app.get('/api/sports/upcoming', async (_req, res) => {
  try {
    let matches = await footballFixtureFeed('upcoming'), provider = 'API-Football';
    if (!matches) {
      const days = await Promise.all([0, 1, 2].map(offset => sportsDay(dateOffset(offset))));
      matches = days.flat().sort((a, b) => new Date(a.kickoff || 0) - new Date(b.kickoff || 0));
      provider = 'TheSportsDB Free';
    }
    res.set('Cache-Control', 'no-store');
    res.json({ matches, updatedAt: new Date().toISOString(), provider, liveOddsConfigured: Boolean(API_FOOTBALL_KEY) });
  } catch (e) {
    res.status(502).json({ error: e.message || 'Could not load upcoming fixtures.' });
  }
});
app.get('/api/sports/odds/:fixtureId', async (req, res) => {
  if (!API_FOOTBALL_KEY) return res.status(503).json({ error: 'Live bookmaker odds are not configured. Add API_FOOTBALL_KEY to Render.' });
  const fixtureId = Number(req.params.fixtureId);
  if (!Number.isSafeInteger(fixtureId) || fixtureId <= 0) return res.status(400).json({ error: 'Invalid fixture ID.' });
  try {
    const [prematch, live] = await Promise.all([
      apiFootball('odds', { fixture: fixtureId }),
      apiFootball('odds/live', { fixture: fixtureId })
    ]);
    res.set('Cache-Control', 'no-store');
    res.json({ fixtureId, prematch, live, updatedAt: new Date().toISOString(), provider: 'API-Football' });
  } catch (e) {
    res.status(502).json({ error: e.message || 'Could not load bookmaker odds.' });
  }
});


const VIRTUAL_TEAMS = {
 football: [['ARS','CHE'],['MCI','LIV'],['MUN','TOT'],['NEW','ARS'],['RMA','BAR'],['ATM','BAY'],['PSG','INT'],['MIL','JUV'],['DOR','CHE'],['LIV','RMA'],['BAR','MCI'],['BAY','MUN']],
 basketball: [['LAL','BOS'],['GSW','CHI'],['MIA','NYK'],['PHX','DAL']],
 tennis: [['ALC','SIN'],['DJK','MED'],['SWA','GAF'],['RUB','TSI']],
 racing: [['Virtual Grand Prix','Virtual Grand Prix']]
};
const VIRTUAL_FOOTBALL_CLUBS = ['ARS','CHE','MCI','LIV','MUN','TOT','NEW','RMA','BAR','ATM','BAY','PSG','INT','MIL','JUV','DOR'];
function virtualClubName(row,side) {
 const raw=String(row[side]||'');
 if(VIRTUAL_FOOTBALL_CLUBS.includes(raw))return raw;
 const digest=crypto.createHash('sha256').update(String(row.match_code||row.id)+':'+side+':'+raw).digest();
 return VIRTUAL_FOOTBALL_CLUBS[digest.readUInt16BE(0)%VIRTUAL_FOOTBALL_CLUBS.length];
}
const RACE_RUNNERS = ['Thunderbolt','Blue Comet','Desert Flame','Silver Arrow','Midnight Star','Golden Dash'];
function makeSeedRandom(seed) {
 let counter=0;
 return () => {
  const bytes=crypto.createHash('sha256').update(seed+':'+counter++).digest();
  return bytes.readUInt32BE(0)/4294967296;
 };
}
function makeVirtualSimulation(sport,seed) {
 const rand=makeSeedRandom(seed), events=[];
 if(sport==='football'){
  let h=0,a=0;
  for(let second=3;second<88;second+=1){
   const n=rand();
   if(n<0.014){const side=rand()<0.5?'home':'away';if(side==='home')h++;else a++;events.push({second,type:'goal',side,text:(side==='home'?'Home':'Away')+' team scores',homeScore:h,awayScore:a});}
   else if(n<0.055)events.push({second,type:rand()<0.5?'save':'chance',side:rand()<0.5?'home':'away',text:rand()<0.5?'A dangerous attack is stopped':'A shot narrowly misses'});
   else if(n<0.061)events.push({second,type:'yellow',side:rand()<0.5?'home':'away',text:'Yellow card shown'});
  }
  return {duration:90,homeScore:h,awayScore:a,participants:[],events,result:{winner:h===a?'draw':h>a?'home':'away',summary:h+' - '+a}};
 }
 if(sport==='basketball'){
  let h=0,a=0;
  for(let second=2;second<47;second+=1){
   if(rand()<0.66){const side=rand()<0.5?'home':'away',points=rand()<0.34?3:2;if(side==='home')h+=points;else a+=points;events.push({second,type:'score',side,points,text:(side==='home'?'Home':'Away')+' scores '+points+' points',homeScore:h,awayScore:a,quarter:Math.min(4,Math.floor(second/12)+1)});}
   else if(rand()<0.12)events.push({second,type:'foul',side:rand()<0.5?'home':'away',text:'Foul called',quarter:Math.min(4,Math.floor(second/12)+1)});
  }
  return {duration:48,homeScore:h,awayScore:a,participants:[],events,result:{winner:h===a?'draw':h>a?'home':'away',summary:h+' - '+a}};
 }
 if(sport==='tennis'){
  const first=rand()<0.5?'home':'away',sets=[];
  let homeSets=0,awaySets=0;
  for(let set=1;set<=3;set++){
   const winner=rand()<0.5?'home':'away',games=6+Math.floor(rand()*2);
   if(winner==='home')homeSets++;else awaySets++;
   sets.push({set,winner,games});
   events.push({second:Math.round(set*26),type:'set',side:winner,text:(winner==='home'?'Home':'Away')+' player wins set '+set,homeSets,awaySets});
   if(homeSets===2||awaySets===2)break;
  }
  return {duration:78,homeScore:homeSets,awayScore:awaySets,participants:[],events,result:{winner:homeSets===awaySets?'draw':homeSets>awaySets?'home':'away',sets,summary:homeSets+' sets - '+awaySets+' sets'}};
 }
 const runners=RACE_RUNNERS.map((name,index)=>({name,index,pace:rand()}));
 const order=[...runners].sort((x,y)=>y.pace-x.pace);
 for(let second=5;second<=40;second+=5){
  const progress=Math.min(99,Math.round(second/45*100));
  const positions=[...runners].sort((x,y)=>(y.pace*progress+rand()*12)-(x.pace*progress+rand()*12)).map(x=>x.name);
  events.push({second,type:'race',progress,positions,text:'Runners pass the '+progress+'% mark'});
 }
 const finish=order.map((x,i)=>({position:i+1,name:x.name}));
 events.push({second:45,type:'finish',finish,text:finish[0].name+' wins the race'});
 return {duration:45,homeScore:0,awayScore:0,participants:RACE_RUNNERS.map(name=>({name})),events,result:{winner:finish[0].name,finish,summary:finish[0].name+' wins'}};
}
function publicVirtualMatch(row,now=new Date()) {
 const started=row.started_at?new Date(row.started_at):null;
 const elapsed=started?Math.max(0,Math.floor((now-started)/1000)):0;
 const visibleEvents=row.status==='scheduled'?[]:(row.events||[]).filter(e=>e.second<=elapsed);
 const lastScore=[...visibleEvents].reverse().find(e=>Number.isInteger(e.homeScore)||Number.isInteger(e.awayScore)||Number.isInteger(e.homeSets)||Number.isInteger(e.awaySets));
 const completed=row.status==='completed';
 const market=crypto.createHash('sha256').update(row.match_code).digest();
 const odds={home:Number((1.55+market[0]/100).toFixed(2)),draw:Number((2.8+market[1]/50).toFixed(2)),away:Number((1.65+market[2]/100).toFixed(2))};
 const runnerOdds=(row.participants||[]).map((runner,index)=>({name:runner.name,odd:Number((2.1+market[(index+3)%market.length]/35).toFixed(2))}));
 return {
  id:row.id,code:row.match_code,sport:row.sport,league:row.league,home:row.sport==='football'?virtualClubName(row,'home'):row.home,away:row.sport==='football'?virtualClubName(row,'away'):row.away,odds,runnerOdds,
  participants:row.participants||[],status:row.status,durationSeconds:row.duration_seconds,elapsedSeconds:Math.min(elapsed,row.duration_seconds),
  homeScore:completed?row.home_score:(lastScore?.homeScore??lastScore?.homeSets??0),awayScore:completed?row.away_score:(lastScore?.awayScore??lastScore?.awaySets??0),
  events:visibleEvents,seedHash:row.seed_hash,seedReveal:completed?row.seed_secret:null,
  result:completed?row.result:null,scheduledAt:row.scheduled_at,startedAt:row.started_at,completedAt:row.completed_at
 };
}
async function ensureVirtualFixtures(sport) {
 const count=await pool.query("SELECT count(*)::int n FROM virtual_matches WHERE sport=$1 AND status='scheduled'",[sport]);
 const needed=Math.max(0,4-count.rows[0].n);
 for(let i=0;i<needed;i++){
  const pair=VIRTUAL_TEAMS[sport][Math.floor(Math.random()*VIRTUAL_TEAMS[sport].length)];
  const seed=crypto.randomBytes(32).toString('hex'),code='SV-'+crypto.randomBytes(5).toString('hex').toUpperCase();
  const raceParticipants=sport==='racing'?RACE_RUNNERS.map(name=>({name})): [];
  await pool.query("INSERT INTO virtual_matches(match_code,sport,league,home,away,participants,duration_seconds,scheduled_at,seed_hash,seed_secret) VALUES($1,$2,$3,$4,$5,$6,$7,NOW()+($8 * INTERVAL '1 minute'),$9,$10) ON CONFLICT(match_code) DO NOTHING",
   [code,sport,sport==='racing'?'SOOTY VIRTUAL GRAND PRIX':'SOOTY VIRTUAL '+sport.toUpperCase(),pair[0],pair[1],JSON.stringify(raceParticipants),sport==='football'?90:sport==='basketball'?48:sport==='tennis'?78:45,i*2,crypto.createHash('sha256').update(seed).digest('hex'),seed]);
 }
}
async function createVirtualFixture(sport,offset=0) {
 const pair=VIRTUAL_TEAMS[sport][Math.floor(Math.random()*VIRTUAL_TEAMS[sport].length)];
 const seed=crypto.randomBytes(32).toString('hex'),code='SV-'+crypto.randomBytes(5).toString('hex').toUpperCase();
 const raceParticipants=sport==='racing'?RACE_RUNNERS.map(name=>({name})): [];
 await pool.query("INSERT INTO virtual_matches(match_code,sport,league,home,away,participants,duration_seconds,scheduled_at,seed_hash,seed_secret) VALUES($1,$2,$3,$4,$5,$6,$7,NOW()+($8 * INTERVAL '1 second'),$9,$10) ON CONFLICT(match_code) DO NOTHING",
  [code,sport,sport==='racing'?'SOOTY VIRTUAL GRAND PRIX':'SOOTY VIRTUAL '+sport.toUpperCase(),pair[0],pair[1],JSON.stringify(raceParticipants),sport==='football'?90:sport==='basketball'?48:sport==='tennis'?78:45,offset,crypto.createHash('sha256').update(seed).digest('hex'),seed]);
}
async function generateVirtualBatch() {
 for(const sport of Object.keys(VIRTUAL_TEAMS)) for(let i=0;i<5;i++) await createVirtualFixture(sport,i*2);
}
generateVirtualBatch().catch(e=>console.error('Initial virtual batch generation failed:',e.message));
const virtualBatchTimer=setInterval(()=>generateVirtualBatch().catch(e=>console.error('Virtual batch generation failed:',e.message)),60000);
virtualBatchTimer.unref();
async function completeVirtualMatchIfDue(row) {
 if(row.status!=='live'||!row.started_at)return row;
 if(Date.now()-new Date(row.started_at).getTime()<row.duration_seconds*1000)return row;
 const updated=await pool.query("UPDATE virtual_matches SET status='completed',completed_at=NOW() WHERE id=$1 AND status='live' RETURNING *",[row.id]);
 return updated.rows[0]||row;
}
app.get('/api/virtual/matches',async(req,res)=>{
 try{
  const sport=cleanText(req.query.sport,20).toLowerCase();
  if(!Object.hasOwn(VIRTUAL_TEAMS,sport))return res.status(400).json({error:'Choose football, basketball, tennis or racing.'});
  await ensureVirtualFixtures(sport);
  const q=await pool.query("SELECT * FROM virtual_matches WHERE sport=$1 AND status<>'completed' ORDER BY CASE status WHEN 'live' THEN 0 ELSE 1 END,scheduled_at DESC,id DESC LIMIT 20",[sport]);
  const rows=await Promise.all(q.rows.map(completeVirtualMatchIfDue));
  res.set('Cache-Control','no-store');res.json({sport,matches:rows.filter(x=>x.status!=='completed').map(x=>publicVirtualMatch(x))});
 }catch(e){res.status(500).json({error:'Could not load virtual fixtures.'});}
});
app.post('/api/virtual/matches/:id/start',async(req,res)=>{
 try{
  const q=await pool.query('SELECT * FROM virtual_matches WHERE id=$1',[req.params.id]);
  if(!q.rowCount)return res.status(404).json({error:'Virtual match not found.'});
  let row=q.rows[0];
  if(row.status==='scheduled'){
   const sim=makeVirtualSimulation(row.sport,row.seed_secret);
   const u=await pool.query("UPDATE virtual_matches SET status='live',started_at=NOW(),home_score=$2,away_score=$3,events=$4,result=$5,participants=$6 WHERE id=$1 AND status='scheduled' RETURNING *",
    [row.id,sim.homeScore,sim.awayScore,JSON.stringify(sim.events),JSON.stringify(sim.result),JSON.stringify(sim.participants)]);
   row=u.rows[0]||row;
  }
  res.set('Cache-Control','no-store');res.json({match:publicVirtualMatch(row)});
 }catch(e){res.status(500).json({error:'Could not start virtual match.'});}
});
app.get('/api/virtual/matches/:id',async(req,res)=>{
 try{
  const q=await pool.query('SELECT * FROM virtual_matches WHERE id=$1',[req.params.id]);
  if(!q.rowCount)return res.status(404).json({error:'Virtual match not found.'});
  const row=await completeVirtualMatchIfDue(q.rows[0]);
  res.set('Cache-Control','no-store');res.json({match:publicVirtualMatch(row)});
 }catch(e){res.status(500).json({error:'Could not load virtual match.'});}
});
app.get('/api/virtual/history',async(_req,res)=>{
 try{
  const q=await pool.query("SELECT * FROM virtual_matches WHERE status='completed' ORDER BY completed_at DESC LIMIT 100");
  res.set('Cache-Control','no-store');res.json({matches:q.rows.map(x=>publicVirtualMatch(x))});
 }catch(e){res.status(500).json({error:'Could not load virtual match history.'});}
});

app.get('/health', (_req,res)=>res.json({ok:true,service:'sooty-bet-api'}));
app.post('/api/auth/register', async (req,res) => {
 try {
  const fullName=cleanText(req.body.fullName,120);
  const email=cleanText(req.body.email,254).toLowerCase();
  const phone=cleanText(req.body.phone,20).replace(/[\s()-]/g,'');
  const country=cleanText(req.body.country,2).toUpperCase()||'NG';
  const referralCode=cleanText(req.body.referralCode,20)||null;
  const password=typeof req.body.password==='string'?req.body.password:'';
  if(fullName.length<2||!/^\S+@\S+\.\S+$/.test(email)||!/^\+?[1-9]\d{7,14}$/.test(phone)||country!=='NG'||password.length<12||req.body.acceptedTerms!==true)
   return res.status(400).json({error:'Check your name, email, Nigerian phone number, password and acceptance of the terms.'});
  const password_hash=await bcrypt.hash(password,12);
  const q=await pool.query('INSERT INTO users(email,phone,password_hash,full_name,country,referral_code,terms_accepted_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) RETURNING id,email,phone,full_name,country,role,status,balance_kobo',[email,phone,password_hash,fullName,country,referralCode]);
  const u=q.rows[0];
  res.status(201).json({token:tokenFor(u),user:{id:u.id,email:u.email,phone:u.phone,fullName:u.full_name,country:u.country,role:u.role,status:u.status}});
 } catch(e) { res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'That email or phone is already registered.':'Could not create account.'}); }
});
app.post('/api/auth/forgot-password', async (req,res) => {
 const email=cleanText(req.body.email,254).toLowerCase();
 const generic={message:'If an account exists for that email, a password reset link will be sent shortly.'};
 if(!/^\\S+@\\S+\\.\\S+$/.test(email)) return res.status(200).json(generic);
 if(!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) return res.status(503).json({error:'Password recovery email is not configured yet. Please contact SORTBET support.'});
 try {
  const q=await pool.query('SELECT id,email,full_name FROM users WHERE lower(email)=$1 LIMIT 1',[email]);
  if(q.rowCount){
   const raw=crypto.randomBytes(32).toString('base64url');
   const tokenHash=crypto.createHash('sha256').update(raw).digest('hex');
   await pool.query("UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL",[q.rows[0].id]);
   await pool.query("INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 minutes')",[q.rows[0].id,tokenHash]);
   const resetUrl='https://sooty-bet.onrender.com/?reset_token='+encodeURIComponent(raw);
   const mail=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+process.env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.EMAIL_FROM,to:[email],subject:'Reset your SORTBET NG password',html:'<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#172538"><h2>Reset your SORTBET NG password</h2><p>We received a request to reset your password. This link expires in 30 minutes and can only be used once.</p><p><a href="'+resetUrl+'" style="display:inline-block;background:#0879df;color:#fff;padding:13px 20px;border-radius:8px;text-decoration:none">Reset password</a></p><p>If you did not request this, you can ignore this email.</p></div>'})});
   if(!mail.ok){const body=await mail.text();console.error('Password reset email failed:',mail.status,body.slice(0,300));return res.status(502).json({error:'Could not send the reset email. Please try again later.'});}
  }
  res.set('Cache-Control','no-store');res.json(generic);
 } catch(e){console.error('Password reset request failed:',e.message);res.status(500).json({error:'Could not process the password reset request.'});}
});
app.post('/api/auth/reset-password', async (req,res) => {
 const raw=typeof req.body.token==='string'?req.body.token:'';
 const password=typeof req.body.password==='string'?req.body.password:'';
 if(raw.length<30 || raw.length>200 || password.length<12) return res.status(400).json({error:'Use a valid reset link and a password with at least 12 characters.'});
 try {
  const tokenHash=crypto.createHash('sha256').update(raw).digest('hex');
  const q=await pool.query("SELECT id,user_id FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() LIMIT 1",[tokenHash]);
  if(!q.rowCount) return res.status(400).json({error:'This reset link is invalid or expired. Please request a new one.'});
  const hash=await bcrypt.hash(password,12);
  await pool.query('BEGIN');
  try {
   const locked=await pool.query("SELECT id,user_id FROM password_reset_tokens WHERE id=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE",[q.rows[0].id]);
   if(!locked.rowCount) throw new Error('RESET_TOKEN_USED');
   await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2',[hash,locked.rows[0].user_id]);
   await pool.query('UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL',[locked.rows[0].user_id]);
   await pool.query('COMMIT');
  } catch(e){await pool.query('ROLLBACK');throw e;}
  res.set('Cache-Control','no-store');res.json({message:'Your password has been reset. You can now log in with your new password.'});
 } catch(e){if(e.message==='RESET_TOKEN_USED')return res.status(400).json({error:'This reset link has already been used. Please request a new one.'});console.error('Password reset failed:',e.message);res.status(500).json({error:'Could not reset your password.'});}
});
app.post('/api/auth/login', async (req,res) => {
 try {
  const identifier = cleanText(req.body.identifier,254).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const q = await pool.query('SELECT * FROM users WHERE lower(coalesce(email,phone))=$1 OR phone=$1 LIMIT 1',[identifier]);
  const u=q.rows[0];
  if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Invalid login details.'});
  res.json({token:tokenFor(u),user:{id:u.id,email:u.email,phone:u.phone,role:u.role,status:u.status}});
 } catch { res.status(500).json({error:'Login failed.'}); }
});
app.get('/api/wallet',auth,async(req,res)=>{
 const q=await pool.query('SELECT balance_kobo FROM users WHERE id=$1',[req.auth.sub]);
 const entries=await pool.query('SELECT type,amount_kobo,reference,description,created_at FROM wallet_ledger WHERE user_id=$1 ORDER BY created_at DESC LIMIT 30',[req.auth.sub]);
 res.json({balanceKobo:q.rows[0]?.balance_kobo||0,entries:entries.rows.map(x=>({type:x.type,amountKobo:x.amount_kobo,reference:x.reference,description:x.description,createdAt:x.created_at}))});
});
app.get('/api/bets',auth,(_req,res)=>res.json([]));
app.get('/api/admin/users/pending-verification',auth,adminOnly,async(_req,res)=>{
 const q=await pool.query("SELECT id,email,phone,created_at FROM users WHERE role='user' AND status='pending_verification' ORDER BY created_at ASC LIMIT 200");
 res.json(q.rows);
});
app.patch('/api/admin/users/:id/verification',auth,adminOnly,async(req,res)=>{
 const decision=cleanText(req.body.decision,20);
 const evidenceChecked=req.body.evidenceChecked===true;
 const note=cleanText(req.body.note,300);
 if(!['approved','rejected'].includes(decision)) return res.status(400).json({error:'Choose approve or reject.'});
 if(!evidenceChecked) return res.status(400).json({error:'Confirm that you reviewed valid age evidence before submitting.'});
 let dob=null;
 if(decision==='approved'){
  const raw=cleanText(req.body.dateOfBirth,10);
  if(!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return res.status(400).json({error:'Enter the date of birth shown on the verified identity document.'});
  const parsed=new Date(raw+'T00:00:00Z');
  if(Number.isNaN(parsed.getTime())||parsed.toISOString().slice(0,10)!==raw) return res.status(400).json({error:'Enter a valid date of birth.'});
  const today=new Date(); let age=today.getUTCFullYear()-parsed.getUTCFullYear();
  const month=today.getUTCMonth()-parsed.getUTCMonth();
  if(month<0||(month===0&&today.getUTCDate()<parsed.getUTCDate())) age--;
  if(age<18) return res.status(403).json({error:'This user is under 18 and cannot be approved.'});
  dob=raw;
 }
 const status=decision==='approved'?'active':'verification_rejected';
 const q=await pool.query("UPDATE users SET status=$1,date_of_birth=$2,verification_reviewed_at=NOW(),verification_note=$3 WHERE id=$4 AND role='user' AND status='pending_verification' RETURNING id,email,phone,status,verification_reviewed_at",[status,dob,note||('Age verification '+decision),req.params.id]);
 if(!q.rowCount) return res.status(404).json({error:'Pending user not found. Refresh the list.'});
 res.json({ok:true,user:q.rows[0],message:decision==='approved'?'Age verified. Account activated.':'Verification rejected.'});
});
app.get('/api/admin/overview',auth,adminOnly,async(_req,res)=>{
 const [users,pendingWithdrawals]=await Promise.all([
  pool.query("SELECT count(*)::int n FROM users WHERE role='user'"),
  pool.query("SELECT count(*)::int n FROM withdrawals WHERE status IN ('pending','approved')")
 ]);
 res.json({users:users.rows[0].n,bets:0,pendingWithdrawals:pendingWithdrawals.rows[0].n,note:'Customer accounts, wallet ledger and withdrawal operations are available. No sportsbook bets are recorded in the server ledger yet.'});
});
app.post('/api/withdrawals',auth,async(req,res)=>{
 const amountNaira=Number(req.body.amount);
 const amountKobo=Math.round(amountNaira*100);
 const bank=cleanText(req.body.bankName,80), accountName=cleanText(req.body.accountName,100), accountNumber=cleanText(req.body.accountNumber,20);
 if (!Number.isSafeInteger(amountKobo)||amountKobo<10000||amountKobo>100000000||!bank||!accountName||!/^[0-9]{10}$/.test(accountNumber))
  return res.status(400).json({error:'Enter a valid amount (minimum ₦100), bank, account name and 10-digit account number.'});
 const client=await pool.connect();
 try {
  await client.query('BEGIN');
  const u=await client.query('SELECT balance_kobo FROM users WHERE id=$1 FOR UPDATE',[req.auth.sub]);
  if (!u.rowCount || BigInt(u.rows[0].balance_kobo)<BigInt(amountKobo)) { await client.query('ROLLBACK'); return res.status(400).json({error:'Insufficient available wallet balance.'}); }
  const reference=ref();
  await client.query('UPDATE users SET balance_kobo=balance_kobo-$1 WHERE id=$2',[amountKobo,req.auth.sub]);
  await client.query('INSERT INTO wallet_ledger(user_id,type,amount_kobo,reference,description) VALUES($1,\'withdrawal_hold\',$2,$3,\'Withdrawal request reserved pending admin review\')',[req.auth.sub,amountKobo,reference]);
  const w=await client.query('INSERT INTO withdrawals(user_id,reference,amount_kobo,bank_name,account_name,account_number) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,reference,amount_kobo,bank_name,account_name,account_number,status,created_at',[req.auth.sub,reference,amountKobo,bank,accountName,accountNumber]);
  await client.query('COMMIT');
  res.status(201).json({withdrawal:{...w.rows[0],amountNaira:amountNaira,createdAt:w.rows[0].created_at}});
 } catch(e) { await client.query('ROLLBACK'); res.status(500).json({error:'Could not submit withdrawal request.'}); }
 finally { client.release(); }
});
app.get('/api/withdrawals',auth,async(req,res)=>{
 const q=await pool.query('SELECT id,reference,amount_kobo,bank_name,account_name,account_number,status,admin_note,created_at,updated_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.auth.sub]);
 res.json(q.rows);
});
app.get('/api/admin/withdrawals',auth,adminOnly,async(_req,res)=>{
 const q=await pool.query('SELECT w.id,w.reference,w.amount_kobo,w.bank_name,w.account_name,w.account_number,w.status,w.admin_note,w.created_at,u.email,u.phone FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY CASE WHEN w.status=\'pending\' THEN 0 WHEN w.status=\'approved\' THEN 1 ELSE 2 END,w.created_at DESC LIMIT 200');
 res.json(q.rows);
});
app.patch('/api/admin/withdrawals/:id',auth,adminOnly,async(req,res)=>{
 const status=cleanText(req.body.status,20), note=cleanText(req.body.note,300);
 if (!['approved','paid','rejected'].includes(status)) return res.status(400).json({error:'Status must be approved, paid or rejected.'});
 const client=await pool.connect();
 try {
  await client.query('BEGIN');
  const q=await client.query('SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE',[req.params.id]);
  if (!q.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({error:'Withdrawal not found.'}); }
  const w=q.rows[0];
  if (w.status==='paid'||w.status==='rejected') { await client.query('ROLLBACK'); return res.status(409).json({error:'This request is already closed.'}); }
  if (status==='paid' && w.status!=='approved') { await client.query('ROLLBACK'); return res.status(409).json({error:'Approve the request first. Transfer the money manually, then mark it paid.'}); }
  if (status==='rejected') {
   await client.query('UPDATE users SET balance_kobo=balance_kobo+$1 WHERE id=$2',[w.amount_kobo,w.user_id]);
   await client.query('INSERT INTO wallet_ledger(user_id,type,amount_kobo,reference,description) VALUES($1,\'withdrawal_refund\',$2,$3,\'Rejected withdrawal returned to wallet\')',[w.user_id,w.amount_kobo,'REF-'+w.reference]);
  }
  await client.query('UPDATE withdrawals SET status=$1,admin_note=$2,reviewed_by=$3,updated_at=NOW() WHERE id=$4',[status,note,req.auth.sub,w.id]);
  await client.query('COMMIT');
  res.json({ok:true,status,message:status==='paid'?'Marked paid. Confirm the bank transfer has actually succeeded.':status==='approved'?'Approved. Make the bank transfer manually before marking paid.':'Rejected; reserved wallet funds returned.'});
 } catch { await client.query('ROLLBACK'); res.status(500).json({error:'Could not update request.'}); }
 finally { client.release(); }
});
app.get('/api/admin/finance',auth,adminOnly,async(_req,res)=>{
 try{
  const [wallet,credits,debits,pending,paid,recent]=await Promise.all([
   pool.query('SELECT COALESCE(SUM(balance_kobo),0)::text total FROM users WHERE role=\'user\''),
   pool.query("SELECT COALESCE(SUM(amount_kobo),0)::text total FROM wallet_ledger WHERE amount_kobo>0"),
   pool.query("SELECT COALESCE(SUM(ABS(amount_kobo)),0)::text total FROM wallet_ledger WHERE amount_kobo<0"),
   pool.query("SELECT count(*)::int n FROM withdrawals WHERE status IN ('pending','approved')"),
   pool.query("SELECT count(*)::int n FROM withdrawals WHERE status='paid'"),
   pool.query("SELECT l.id,l.type,l.amount_kobo,l.reference,l.description,l.created_at,u.email,u.phone FROM wallet_ledger l JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 60")
  ]);
  res.json({walletLiabilityKobo:wallet.rows[0].total,totalCreditsKobo:credits.rows[0].total,totalDebitsKobo:debits.rows[0].total,pendingWithdrawals:pending.rows[0].n,paidWithdrawals:paid.rows[0].n,recentTransactions:recent.rows});
 }catch(e){console.error('Admin finance overview failed:',e.message);res.status(500).json({error:'Could not load financial overview.'});}
});
app.get('/api/admin/customers',auth,adminOnly,async(_req,res)=>{
 try{
  const q=await pool.query("SELECT id,full_name,email,phone,country,status,balance_kobo,created_at FROM users WHERE role='user' ORDER BY created_at DESC LIMIT 250");
  res.json(q.rows);
 }catch(e){res.status(500).json({error:'Could not load customer accounts.'});}
});
app.listen(PORT,'0.0.0.0',()=>console.log('SOOTY BET API listening on '+PORT));
