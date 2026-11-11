import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, closeSync, constants, lstatSync, mkdirSync, openSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { Adapter, AdapterPayload } from 'oidc-provider';

/** One database per issuer. Deploy on local storage, not a network filesystem. */
export class AuthStore {
  private readonly db: DatabaseSync;
  private readonly encryptionKey: Buffer;
  private readonly indexKey: Buffer;
  constructor(path: string, key: Buffer) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('32-byte database key required');
    this.encryptionKey = createHmac('sha256',key).update('dot-feishu-db-encryption-v1').digest();
    this.indexKey = createHmac('sha256',key).update('dot-feishu-db-index-v1').digest();
    if (path === ':memory:') throw new Error('Persistent authorization database required');
    path = resolve(path);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    closeSync(fd);
    if (!lstatSync(path).isFile()) throw new Error('Invalid authorization database');
    chmodSync(path, 0o600);
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS auth_records (
        model TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
        expires INTEGER, grant_id TEXT, uid TEXT, user_code TEXT, consumed INTEGER,
        PRIMARY KEY (model,id));
      CREATE INDEX IF NOT EXISTS auth_grants ON auth_records(grant_id);
      CREATE INDEX IF NOT EXISTS auth_uids ON auth_records(model,uid);
      CREATE INDEX IF NOT EXISTS auth_codes ON auth_records(model,user_code);
      CREATE INDEX IF NOT EXISTS auth_expiry ON auth_records(expires);
      CREATE TABLE IF NOT EXISTS auth_revoked (id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS auth_context (name TEXT PRIMARY KEY, value TEXT NOT NULL);`);
    const mode = `aes256gcm-v1:${createHmac('sha256',key).update('dot-feishu-db-key-check-v1').digest('hex')}`;
    const savedMode = this.db.prepare("SELECT value FROM auth_context WHERE name='storage_mode'").get();
    const count = this.db.prepare('SELECT COUNT(*) AS n FROM auth_records').get();
    if ((savedMode && savedMode.value !== mode) || (!savedMode && Number(count?.n))) {
      this.db.close(); throw new Error('Authorization database encryption mode or key mismatch');
    }
    this.db.prepare("INSERT OR IGNORE INTO auth_context(name,value) VALUES ('storage_mode',?)").run(mode);
  }
  private index(value: string): string {
    return createHmac('sha256',this.indexKey).update(value).digest('hex');
  }
  private encode(model: string, id: string, payload: object): string {
    const json = JSON.stringify(payload);
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm',this.encryptionKey,iv);
    cipher.setAAD(Buffer.from(`${model}:${this.index(id)}`));
    const ciphertext = Buffer.concat([cipher.update(json,'utf8'),cipher.final()]);
    return 'gcm-v1:' + Buffer.concat([iv,cipher.getAuthTag(),ciphertext]).toString('base64');
  }
  private decode(model: string, indexedId: string, stored: string): AdapterPayload {
    if (!stored.startsWith('gcm-v1:')) throw new Error('Invalid encrypted authorization record');
    const value = Buffer.from(stored.slice(7),'base64');
    const decipher = createDecipheriv('aes-256-gcm',this.encryptionKey,value.subarray(0,12));
    decipher.setAAD(Buffer.from(`${model}:${indexedId}`)); decipher.setAuthTag(value.subarray(12,28));
    return JSON.parse(Buffer.concat([decipher.update(value.subarray(28)),decipher.final()]).toString('utf8')) as AdapterPayload;
  }
  bindIssuer(issuer: string) {
    this.db.prepare('INSERT OR IGNORE INTO auth_context(name,value) VALUES (?,?)').run('issuer', issuer);
    const row = this.db.prepare('SELECT value FROM auth_context WHERE name=?').get('issuer');
    if (row?.value !== issuer) throw new Error('Authorization database belongs to another issuer');
  }
  /** Atomic total cap and persisted rate limit across process restarts. */
  registerClient(id: string, payload: object) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare("DELETE FROM auth_records WHERE model='Client' AND expires IS NOT NULL AND expires<=?").run(Math.floor(Date.now()/1000));
      const count = this.db.prepare("SELECT COUNT(*) AS n FROM auth_records WHERE model='Client'").get();
      const row = this.db.prepare("SELECT value FROM auth_context WHERE name='registration_times'").get();
      const now = Date.now();
      const times = row ? (JSON.parse(String(row.value)) as number[]).filter(t => t > now - 60000) : [];
      if (Number(count?.n) >= 100 || times.length >= 10) { this.db.exec('ROLLBACK'); return false; }
      times.push(now);
      this.db.prepare("INSERT INTO auth_context(name,value) VALUES ('registration_times',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value").run(JSON.stringify(times));
      this.db.prepare("INSERT INTO auth_records(model,id,payload,expires) VALUES ('Client',?,?,?)").run(this.index(id),this.encode('Client',id,payload),Math.floor(now/1000)+3600);
      this.db.exec('COMMIT'); return true;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  adapter = (model: string): Adapter => ({
    upsert: async (id, payload, expiresIn) => {
      this.db.prepare('DELETE FROM auth_records WHERE expires<=?').run(Math.floor(Date.now()/1000));
      const grantId = model === 'Grant' ? id : payload.grantId;
      if (grantId && this.db.prepare('SELECT id FROM auth_revoked WHERE id=?').get(this.index(grantId))) {
        throw new Error('Authorization grant revoked');
      }
      this.db.prepare(`INSERT INTO auth_records(model,id,payload,expires,grant_id,uid,user_code,consumed)
        VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(model,id) DO UPDATE SET payload=excluded.payload,
        expires=excluded.expires,grant_id=excluded.grant_id,uid=excluded.uid,user_code=excluded.user_code,
        consumed=COALESCE(auth_records.consumed,excluded.consumed)`).run(
        model, this.index(id), this.encode(model,id,payload), typeof expiresIn === 'number' ? Math.floor(Date.now()/1000)+expiresIn : null,
        grantId ? this.index(grantId) : null, payload.uid ? this.index(payload.uid) : null, payload.userCode ? this.index(payload.userCode) : null, payload.consumed ?? null,
      );
      // Grants are saved only after the fixed owner has approved client consent.
      // A linked client must survive the one-hour unauthenticated registration TTL.
      if (model === 'Grant' && typeof payload.clientId === 'string' && payload.accountId) {
        this.db.prepare("UPDATE auth_records SET expires=NULL WHERE model='Client' AND id=?").run(this.index(payload.clientId));
      }
    },
    find: async (id) => this.find(model, 'id', id),
    findByUid: async (uid) => this.find(model, 'uid', uid),
    findByUserCode: async (code) => this.find(model, 'user_code', code),
    consume: async (id) => {
      const result = this.db.prepare('UPDATE auth_records SET consumed=? WHERE model=? AND id=? AND consumed IS NULL')
        .run(Math.floor(Date.now()/1000), model, this.index(id));
      if (!result.changes) throw new Error('Authorization artifact already consumed');
    },
    destroy: async (id) => { this.db.prepare('DELETE FROM auth_records WHERE model=? AND id=?').run(model,this.index(id)); },
    revokeByGrantId: async (id) => {
      this.db.exec('BEGIN IMMEDIATE');
      try {
        this.db.prepare('INSERT OR IGNORE INTO auth_revoked(id) VALUES (?)').run(this.index(id));
        this.db.prepare('DELETE FROM auth_records WHERE grant_id=?').run(this.index(id));
        this.db.exec('COMMIT');
      } catch (error) { this.db.exec('ROLLBACK'); throw error; }
    },
  });
  private find(model: string, column: 'id'|'uid'|'user_code', value: string): AdapterPayload | undefined {
    const row = this.db.prepare(`SELECT id,payload,consumed FROM auth_records WHERE model=? AND ${column}=?
      AND (expires IS NULL OR expires>?) AND NOT EXISTS (SELECT 1 FROM auth_revoked WHERE id=grant_id) LIMIT 1`)
      .get(model, this.index(value), Math.floor(Date.now()/1000));
    if (!row) return undefined;
    const payload = this.decode(model,String(row.id),String(row.payload));
    if (row.consumed !== null) payload.consumed = Number(row.consumed);
    return payload;
  }
  /** Atomic single-use state / CSRF claim; never exposes a consumed value again. */
  async take(model: string, id: string): Promise<AdapterPayload | undefined> {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const value = this.find(model, 'id', id);
      this.db.prepare('DELETE FROM auth_records WHERE model=? AND id=?').run(model,this.index(id));
      this.db.exec('COMMIT');
      return value;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  close() { this.db.close(); }
}
