import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { GoogleGenAI, Type } from '@google/genai';
import { createServer as createViteServer } from 'vite';
import { SCHEMES_DATABASE } from './src/data/schemes.ts';
import { createEmptyProfile, evaluateAllSchemes } from './src/utils/eligibilityEngine.ts';
import type { EligibilityEvaluation, Language, UserProfile } from './src/types/scheme.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.resolve(__dirname, 'data');
const DB_FILE = path.resolve(DATA_DIR, 'schemesathi-db.json');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

interface StoredUser {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  profile: UserProfile;
  savedSchemeIds: string[];
  createdAt: string;
}

interface DbSchema {
  users: StoredUser[];
}

function ensureDataFile(): DbSchema {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const initial: DbSchema = { users: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw) as DbSchema;
    return Array.isArray(parsed.users) ? parsed : { users: [] };
  } catch {
    return { users: [] };
  }
}

function saveDb(db: DbSchema): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  const tmpPath = path.resolve(DATA_DIR, `schemesathi-db.${process.pid}.tmp`);
  if (!tmpPath.startsWith(DATA_DIR + path.sep)) {
    throw new Error('Invalid database path');
  }
  fs.writeFileSync(tmpPath, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmpPath, DB_FILE);
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  const keyBuf = Buffer.from(keyHex, 'hex');
  const derivedBuf = crypto.scryptSync(password, salt, 64);
  if (keyBuf.length !== derivedBuf.length) return false;
  return crypto.timingSafeEqual(keyBuf, derivedBuf);
}

function signToken(userId: string): string {
  const exp = Date.now() + 1000 * 60 * 60 * 24 * 7; // 7 days
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token: string): { sub: string } | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      sub?: string;
      exp?: number;
    };
    if (!decoded.sub || !decoded.exp || decoded.exp < Date.now()) {
      return null;
    }
    return { sub: decoded.sub };
  } catch {
    return null;
  }
}

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.cookie;
  if (!header) return {};
  const result: Record<string, string> = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const key = part.slice(0, idx).trim();
      const val = part.slice(idx + 1).trim();
      result[key] = decodeURIComponent(val);
    }
  }
  return result;
}

interface AuthedRequest extends Request {
  userId?: string;
}

function extractAuth(req: AuthedRequest, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const verified = verifyToken(token);
    if (verified) {
      req.userId = verified.sub;
      next();
      return;
    }
  }

  const cookies = parseCookies(req);
  if (cookies.ss_session) {
    // Require custom header on cookie-authenticated mutations for CSRF protection
    const isMutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
    const hasCustomHeader = req.headers['x-requested-with'] === 'SchemeSathi';
    if (!isMutation || hasCustomHeader) {
      const verified = verifyToken(cookies.ss_session);
      if (verified) {
        req.userId = verified.sub;
      }
    }
  }
  next();
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (!req.userId) {
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
    return;
  }
  next();
}

function setSessionCookie(req: Request, res: Response, token: string): void {
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production';
  const parts = [
    `ss_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    `Max-Age=${60 * 60 * 24 * 7}`,
  ];
  if (isHttps) {
    parts.push('Secure', 'SameSite=None', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(req: Request, res: Response): void {
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production';
  const parts = ['ss_session=', 'Path=/', 'HttpOnly', 'Max-Age=0'];
  if (isHttps) {
    parts.push('Secure', 'SameSite=None', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

function sanitizeProfile(input: unknown): UserProfile {
  const empty = createEmptyProfile();
  if (!input || typeof input !== 'object') return empty;
  const raw = input as Record<string, unknown>;
  const fd =
    raw.familyDetails && typeof raw.familyDetails === 'object'
      ? (raw.familyDetails as Record<string, unknown>)
      : {};

  const parseBoolOrNull = (val: unknown): boolean | null => {
    if (val === true) return true;
    if (val === false) return false;
    return null;
  };

  const ageNum =
    typeof raw.age === 'number' && Number.isFinite(raw.age) && raw.age >= 0 && raw.age <= 120
      ? Math.floor(raw.age)
      : null;

  const incomeNum =
    typeof raw.annualIncome === 'number' &&
    Number.isFinite(raw.annualIncome) &&
    raw.annualIncome >= 0 &&
    raw.annualIncome <= 100000000
      ? Math.floor(raw.annualIncome)
      : null;

  const famSize =
    typeof fd.familySize === 'number' &&
    Number.isFinite(fd.familySize) &&
    fd.familySize >= 1 &&
    fd.familySize <= 30
      ? Math.floor(fd.familySize)
      : null;

  const genderVal =
    raw.gender === 'Male' || raw.gender === 'Female' || raw.gender === 'Other' ? raw.gender : '';

  return {
    name: typeof raw.name === 'string' ? raw.name.trim().slice(0, 100) : '',
    age: ageNum,
    gender: genderVal,
    state: typeof raw.state === 'string' ? raw.state.trim().slice(0, 80) : 'Andhra Pradesh',
    district: typeof raw.district === 'string' ? raw.district.trim().slice(0, 80) : '',
    annualIncome: incomeNum,
    occupation: typeof raw.occupation === 'string' ? raw.occupation.trim().slice(0, 80) : '',
    educationLevel:
      typeof raw.educationLevel === 'string' ? raw.educationLevel.trim().slice(0, 80) : '',
    socialCategory:
      typeof raw.socialCategory === 'string' ? raw.socialCategory.trim().slice(0, 60) : '',
    familyDetails: {
      hasRationCard: parseBoolOrNull(fd.hasRationCard),
      ownsAgriculturalLand: parseBoolOrNull(fd.ownsAgriculturalLand),
      hasGirlChildUnder10: parseBoolOrNull(fd.hasGirlChildUnder10),
      isBplFamily: parseBoolOrNull(fd.isBplFamily),
      hasDifferentlyAbledMember: parseBoolOrNull(fd.hasDifferentlyAbledMember),
      isPregnantOrLactatingMother: parseBoolOrNull(fd.isPregnantOrLactatingMother),
      familySize: famSize,
    },
  };
}

function getGeminiClient(): GoogleGenAI | null {
  const key = process.env.GEMINI_API_KEY?.trim();
  if (!key || key === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey: key,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function buildDemoChatReply(
  userMessage: string,
  language: Language,
  profile?: UserProfile
): { reply: string; relatedSchemeIds: string[] } {
  const q = userMessage.toLowerCase();
  const isTelugu =
    language === 'te' || /[\u0C00-\u0C7F]/.test(userMessage);

  // Score schemes by keyword relevance in EN and TE
  const scored = SCHEMES_DATABASE.map((s) => {
    let score = 0;
    const hay = `${s.name} ${s.nameTe} ${s.category} ${s.level} ${s.description} ${s.descriptionTe} ${s.benefitHighlight} ${s.requiredDocuments.join(' ')} ${s.eligibilityCriteria.join(' ')}`.toLowerCase();
    const tokens = q.split(/[\s,?.!]+/).filter((t) => t.length >= 2);
    for (const token of tokens) {
      if (hay.includes(token)) score += 3;
      if (s.name.toLowerCase().includes(token) || s.nameTe.toLowerCase().includes(token)) {
        score += 6;
      }
    }
    if ((q.includes('farmer') || q.includes('kisan') || q.includes('రైతు') || q.includes('వ్యవసాయ')) && s.category === 'Agriculture') {
      score += 8;
    }
    if ((q.includes('student') || q.includes('scholarship') || q.includes('college') || q.includes('విద్య') || q.includes('స్కాలర్')) && s.category === 'Education and Scholarships') {
      score += 8;
    }
    if ((q.includes('women') || q.includes('woman') || q.includes('girl') || q.includes('mother') || q.includes('మహిళ') || q.includes('ఆడపిల్ల')) && s.category === 'Women Welfare') {
      score += 8;
    }
    if ((q.includes('health') || q.includes('hospital') || q.includes('medical') || q.includes('ఆరోగ్య') || q.includes('వైద్య')) && s.category === 'Healthcare') {
      score += 8;
    }
    if ((q.includes('house') || q.includes('home') || q.includes('housing') || q.includes('ఇల్లు') || q.includes('గృహ')) && s.category === 'Housing') {
      score += 8;
    }
    if ((q.includes('loan') || q.includes('business') || q.includes('job') || q.includes('artisan') || q.includes('రుణ') || q.includes('ఉపాధి')) && s.category === 'Employment') {
      score += 8;
    }
    if ((q.includes('pension') || q.includes('insurance') || q.includes('పెన్షన్') || q.includes('బీమా')) && s.category === 'Financial Assistance') {
      score += 8;
    }
    if ((q.includes('andhra') || q.includes('ap ') || q.includes('ఆంధ్రప్రదేశ్') || q.includes('ఏపీ')) && s.level === 'Andhra Pradesh') {
      score += 5;
    }
    return { scheme: s, score };
  })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);

  let topSchemes = scored.slice(0, 3).map((x) => x.scheme);

  // If no direct keyword matches, use profile or highlight popular schemes
  if (topSchemes.length === 0 && profile) {
    const evals = evaluateAllSchemes(SCHEMES_DATABASE, profile)
      .filter((e) => e.status === 'Potentially Eligible')
      .slice(0, 3);
    topSchemes = evals
      .map((e) => SCHEMES_DATABASE.find((s) => s.id === e.schemeId))
      .filter((s): s is NonNullable<typeof s> => Boolean(s));
  }
  if (topSchemes.length === 0) {
    topSchemes = SCHEMES_DATABASE.slice(0, 3);
  }

  const wantsDocs =
    q.includes('document') || q.includes('papers') || q.includes('పత్రాలు') || q.includes('డాక్యుమెంట్');
  const wantsApply =
    q.includes('apply') || q.includes('how to') || q.includes('procedure') || q.includes('దరఖాస్తు') || q.includes('ఎలా');

  if (isTelugu) {
    const blocks = topSchemes.map((s) => {
      const lines = [
        `• ${s.nameTe} (${s.level === 'Andhra Pradesh' ? 'ఆంధ్రప్రదేశ్' : 'కేంద్ర ప్రభుత్వం'})`,
        `  ప్రయోజనం: ${s.benefitHighlightTe}`,
        `  అర్హత: ${s.eligibilityCriteriaTe[0]}`,
      ];
      if (wantsDocs) {
        lines.push(`  అవసరమైన పత్రాలు: ${s.requiredDocumentsTe.join(', ')}`);
      } else if (wantsApply) {
        lines.push(`  దరఖాస్తు విధానం: ${s.applicationStepsTe.join(' → ')}`);
      } else {
        lines.push(`  అవసరమైన పత్రాలు: ${s.requiredDocumentsTe.slice(0, 3).join(', ')}`);
      }
      lines.push(`  అధికారిక వెబ్‌సైట్: ${s.officialUrl}`);
      return lines.join('\n');
    });

    return {
      reply: `మీ ప్రశ్నకు సంబంధించి మా ధృవీకరించబడిన డేటాబేస్ నుండి ప్రధాన పథకాలు ఇవిగో:\n\n${blocks.join('\n\n')}\n\nగమనిక: ఇది ప్రాథమిక సమాచారం మాత్రమే. తుది అర్హతను సంబంధిత అధికారిక పోర్టల్ లేదా గ్రామ/వార్డు సచివాలయంలో నిర్ధారించుకోండి.`,
      relatedSchemeIds: topSchemes.map((s) => s.id),
    };
  }

  const blocks = topSchemes.map((s) => {
    const lines = [
      `• ${s.name} (${s.level})`,
      `  Benefit: ${s.benefitHighlight}`,
      `  Key Eligibility: ${s.eligibilityCriteria[0]}`,
    ];
    if (wantsDocs) {
      lines.push(`  Required Documents: ${s.requiredDocuments.join(', ')}`);
    } else if (wantsApply) {
      lines.push(`  How to Apply: ${s.applicationSteps.join(' -> ')}`);
    } else {
      lines.push(`  Key Documents: ${s.requiredDocuments.slice(0, 3).join(', ')}`);
    }
    lines.push(`  Official Portal: ${s.officialUrl}`);
    return lines.join('\n');
  });

  return {
    reply: `Here are the most relevant verified schemes from the SchemeSathi database for your query:\n\n${blocks.join('\n\n')}\n\nAdvisory Note: Eligibility shown here is indicative based on scheme guidelines. Please confirm final eligibility and submit applications only through the official government portals listed above.`,
    relatedSchemeIds: topSchemes.map((s) => s.id),
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(extractAuth);

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      aiConfigured: Boolean(getGeminiClient()),
      schemeCount: SCHEMES_DATABASE.length,
    });
  });

  // Public schemes endpoint
  app.get('/api/schemes', (_req, res) => {
    res.json({ schemes: SCHEMES_DATABASE });
  });

  // Auth: Register
  app.post('/api/auth/register', (req: AuthedRequest, res: Response) => {
    const { name, email, password, profile } = req.body ?? {};
    if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 80) {
      res.status(400).json({ error: 'Please enter a valid full name (at least 2 characters).' });
      return;
    }
    if (
      typeof email !== 'string' ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      email.length > 120
    ) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    if (typeof password !== 'string' || password.length < 6 || password.length > 100) {
      res.status(400).json({ error: 'Password must be at least 6 characters long.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const db = ensureDataFile();
    if (db.users.some((u) => u.email === normalizedEmail)) {
      res.status(409).json({ error: 'An account with this email already exists.' });
      return;
    }

    const sanitized = sanitizeProfile(profile);
    if (!sanitized.name) sanitized.name = name.trim();

    const newUser: StoredUser = {
      id: crypto.randomUUID(),
      name: name.trim(),
      email: normalizedEmail,
      passwordHash: hashPassword(password),
      profile: sanitized,
      savedSchemeIds: Array.isArray(req.body?.savedSchemeIds)
        ? req.body.savedSchemeIds.filter(
            (id: unknown): id is string =>
              typeof id === 'string' && SCHEMES_DATABASE.some((s) => s.id === id)
          )
        : [],
      createdAt: new Date().toISOString(),
    };

    db.users.push(newUser);
    saveDb(db);

    const token = signToken(newUser.id);
    setSessionCookie(req, res, token);

    res.status(201).json({
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        profile: newUser.profile,
        savedSchemeIds: newUser.savedSchemeIds,
      },
    });
  });

  // Auth: Login
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { email, password } = req.body ?? {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const db = ensureDataFile();
    const user = db.users.find((u) => u.email === normalizedEmail);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    const token = signToken(user.id);
    setSessionCookie(req, res, token);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        profile: user.profile,
        savedSchemeIds: user.savedSchemeIds,
      },
    });
  });

  // Auth: Logout
  app.post('/api/auth/logout', (req: Request, res: Response) => {
    clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // Auth: Current user
  app.get('/api/auth/me', (req: AuthedRequest, res: Response) => {
    if (!req.userId) {
      res.json({ user: null });
      return;
    }
    const db = ensureDataFile();
    const user = db.users.find((u) => u.id === req.userId);
    if (!user) {
      res.json({ user: null });
      return;
    }
    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        profile: user.profile,
        savedSchemeIds: user.savedSchemeIds,
      },
    });
  });

  // Update personal details profile
  app.put('/api/profile', requireAuth, (req: AuthedRequest, res: Response) => {
    const db = ensureDataFile();
    const user = db.users.find((u) => u.id === req.userId);
    if (!user) {
      res.status(404).json({ error: 'User account not found.' });
      return;
    }
    user.profile = sanitizeProfile(req.body?.profile);
    saveDb(db);
    res.json({ profile: user.profile });
  });

  // Save a scheme
  app.post('/api/saved-schemes/:schemeId', requireAuth, (req: AuthedRequest, res: Response) => {
    const { schemeId } = req.params;
    if (!SCHEMES_DATABASE.some((s) => s.id === schemeId)) {
      res.status(404).json({ error: 'Scheme not found.' });
      return;
    }
    const db = ensureDataFile();
    const user = db.users.find((u) => u.id === req.userId);
    if (!user) {
      res.status(404).json({ error: 'User account not found.' });
      return;
    }
    if (!user.savedSchemeIds.includes(schemeId)) {
      user.savedSchemeIds.push(schemeId);
      saveDb(db);
    }
    res.json({ savedSchemeIds: user.savedSchemeIds });
  });

  // Remove a saved scheme
  app.delete('/api/saved-schemes/:schemeId', requireAuth, (req: AuthedRequest, res: Response) => {
    const { schemeId } = req.params;
    const db = ensureDataFile();
    const user = db.users.find((u) => u.id === req.userId);
    if (!user) {
      res.status(404).json({ error: 'User account not found.' });
      return;
    }
    user.savedSchemeIds = user.savedSchemeIds.filter((id) => id !== schemeId);
    saveDb(db);
    res.json({ savedSchemeIds: user.savedSchemeIds });
  });

  // AI-based Scheme Recommendations
  app.post('/api/ai/recommend', async (req: Request, res: Response) => {
    const profile = sanitizeProfile(req.body?.profile);
    const language: Language = req.body?.language === 'te' ? 'te' : 'en';
    const evaluations = evaluateAllSchemes(SCHEMES_DATABASE, profile);

    const ai = getGeminiClient();
    if (!ai) {
      res.json({
        mode: 'demo',
        evaluations,
        aiInsights: {},
      });
      return;
    }

    try {
      const candidateIds = evaluations
        .filter((e) => e.status !== 'Not Eligible')
        .slice(0, 8)
        .map((e) => e.schemeId);

      const compactSchemes = SCHEMES_DATABASE.filter((s) => candidateIds.includes(s.id)).map(
        (s) => ({
          id: s.id,
          name: s.name,
          level: s.level,
          category: s.category,
          benefit: s.benefitHighlight,
          criteria: s.eligibilityCriteria,
        })
      );

      const compactEvals = evaluations
        .filter((e) => candidateIds.includes(e.schemeId))
        .map((e) => ({
          schemeId: e.schemeId,
          status: e.status,
          matched: e.matchedConditions,
          missing: e.missingInfo,
        }));

      const prompt = `You are SchemeSathi AI, an advisory assistant for Indian government schemes.
Analyze the citizen profile and the deterministic eligibility evaluations below.
Respond ONLY in ${language === 'te' ? 'Telugu (తెలుగు)' : 'English'}.
For each scheme in the evaluation list, write a concise 1–2 sentence personalized "whyRecommended" explanation grounded strictly in the provided scheme facts and profile, and remind the citizen that this indicates potential eligibility only (never guaranteed approval).

Citizen Profile:
${JSON.stringify(profile)}

Candidate Schemes:
${JSON.stringify(compactSchemes)}

Evaluations:
${JSON.stringify(compactEvals)}`;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                schemeId: { type: Type.STRING },
                whyRecommended: { type: Type.STRING },
              },
              required: ['schemeId', 'whyRecommended'],
            },
          },
        },
      });

      const parsed = JSON.parse((response.text ?? '[]').trim()) as Array<{
        schemeId: string;
        whyRecommended: string;
      }>;
      const aiInsights: Record<string, string> = {};
      for (const item of parsed) {
        if (item.schemeId && item.whyRecommended) {
          aiInsights[item.schemeId] = item.whyRecommended;
        }
      }

      res.json({
        mode: 'gemini',
        evaluations,
        aiInsights,
      });
    } catch (err) {
      console.error('Gemini recommendation error:', err);
      res.json({
        mode: 'demo',
        evaluations,
        aiInsights: {},
        notice: 'Switched to rule-based Demo Mode because the AI service could not be reached.',
      });
    }
  });

  // AI Chatbot
  app.post('/api/ai/chat', async (req: Request, res: Response) => {
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!message || message.length > 1500) {
      res.status(400).json({ error: 'Please enter a valid question (up to 1500 characters).' });
      return;
    }
    const language: Language = req.body?.language === 'te' ? 'te' : 'en';
    const profile = req.body?.profile ? sanitizeProfile(req.body.profile) : undefined;
    const history: Array<{ role: 'user' | 'assistant'; content: string }> = Array.isArray(
      req.body?.history
    )
      ? (req.body.history as unknown[])
          .slice(-6)
          .filter(
            (m: unknown): m is { role: 'user' | 'assistant'; content: string } =>
              Boolean(
                m &&
                  typeof m === 'object' &&
                  ((m as { role?: unknown }).role === 'user' ||
                    (m as { role?: unknown }).role === 'assistant') &&
                  typeof (m as { content?: unknown }).content === 'string'
              )
          )
      : [];

    const ai = getGeminiClient();
    if (!ai) {
      const demo = buildDemoChatReply(message, language, profile);
      res.json({
        mode: 'demo',
        reply: demo.reply,
        relatedSchemeIds: demo.relatedSchemeIds,
      });
      return;
    }

    try {
      const dbSummary = SCHEMES_DATABASE.map((s) => ({
        id: s.id,
        name: s.name,
        nameTe: s.nameTe,
        level: s.level,
        category: s.category,
        department: s.department,
        benefit: s.benefitHighlight,
        eligibility: s.eligibilityCriteria,
        documents: s.requiredDocuments,
        steps: s.applicationSteps,
        officialUrl: s.officialUrl,
        verificationStatus: s.verificationStatus,
      }));

      const systemInstruction = `You are SchemeSathi AI, a helpful, trustworthy Indian Government Scheme Assistant supporting English and Telugu.
STRICT GROUNDING RULES:
1. Answer ONLY using the verified schemes database provided below. Never invent scheme names, benefit amounts, dates, or government URLs.
2. If a user asks about something outside this database or an unverified rule, clearly say "Verification Required on the official portal" and do not guess.
3. Explain eligibility in simple, citizen-friendly language, list required documents clearly, and provide step-by-step application guidance with the official URL from the database.
4. Always distinguish potential eligibility from official approval—never guarantee sanction.
5. Respond in Telugu (తెలుగు) if the user writes in Telugu or if language preference is 'te'; otherwise respond in clear English.

Verified Schemes Database:
${JSON.stringify(dbSummary)}

${profile ? `Current Citizen Profile Context:\n${JSON.stringify(profile)}` : ''}`;

      const conversationPrompt = [
        ...history.map((h) => `${h.role === 'user' ? 'Citizen' : 'Assistant'}: ${h.content}`),
        `Citizen: ${message}`,
      ].join('\n\n');

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: conversationPrompt,
        config: {
          systemInstruction,
        },
      });

      const replyText = response.text?.trim();
      if (!replyText) {
        throw new Error('Empty AI response');
      }

      const relatedIds = SCHEMES_DATABASE.filter(
        (s) =>
          replyText.toLowerCase().includes(s.name.toLowerCase()) ||
          replyText.includes(s.nameTe) ||
          replyText.includes(s.id)
      )
        .slice(0, 3)
        .map((s) => s.id);

      res.json({
        mode: 'gemini',
        reply: replyText,
        relatedSchemeIds: relatedIds,
      });
    } catch (err) {
      console.error('Gemini chat error:', err);
      const demo = buildDemoChatReply(message, language, profile);
      res.json({
        mode: 'demo',
        reply: demo.reply,
        relatedSchemeIds: demo.relatedSchemeIds,
        notice: 'Switched to Demo Mode because the AI service returned an error.',
      });
    }
  });

  // Vite dev middleware or production static assets
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SchemeSathi AI server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
