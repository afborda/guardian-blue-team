import { initDatabase, db } from '../src/database/connection.js';
import { socServers } from '../src/database/guardian-schema.js';

await initDatabase();
const servers = await db.select().from(socServers);
console.log(JSON.stringify(
  servers.map(s => ({ id: s.id, name: s.name, host: s.host, installMode: s.installMode, sshUser: s.sshUser, sshKeyPath: s.sshKeyPath })),
  null, 2
));
