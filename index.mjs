import cors from 'cors';
import bodyParser from 'body-parser';
import express from 'express';
import fetch from 'node-fetch';
import cryptojs from 'crypto-js';
import fnbr from 'fnbr';
const { Client } = fnbr;
import cookieparser from 'cookie-parser';
import moment from 'moment';
import sessionexpress from 'express-session';
import uuid from 'uuid';
import path from 'path';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';
import fs from 'fs';
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const env = process.env;

const app = express();

let sessions = [];
const queues = {};
const accountsSessions = {[env.AUTH_DISCORD]: {
  user: 'CREATOR',
  id: 'CREATORID'
}};

app.set('trust proxy', 1);
app.use(cookieparser());
app.use(sessionexpress({
  secret: 'yayyapay2=4',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'strict'
  }
}));

app.use(cors({credentials: true, origin: 'https://dashboard.webfort.app'})); 

app.use(bodyParser.json());

let ress = null;

function write(data) {
  if(ress) ress.write(`data: ${JSON.stringify(data)}\n\n`);
}

const statusCodetoObject = {
  401: {
    error: 'webfort.errors.auth.required',
    message: 'Please use the account that created this bot!'
  },
  529: {
    error: 'webfort.accounts.used',
    message: 'You are already using this bot!'
  },
  404: {
    error: 'webfort.action.notFound',
    message: 'The action or thing is not found.'
  },
  400: {
    error: 'webfort.request.parameters',
    message: 'You need to send the requested parameters!'
  }
}

function throwError(res, statusCode, customMessage) {
  return res.status(statusCode).send({
    ...statusCodetoObject[statusCode],
    statusCode,
    ...customMessage ? {
      message: customMessage
    } : {}
  });
}

async function hidePlayer(id, client) {
  client.party.meta.updateSquadAssignments = () => {
      const assignments = [];
      let i = 0;
      assignments.push({
        memberId: client.party.Client.user.id,
        absoluteMemberIdx: 0,
      });
      client.party.members.forEach((m) => {
        if (m.id !== client.party.Client.user.id && !m.hidden) {
          i += 1;
          assignments.push({
            memberId: m.id,
            absoluteMemberIdx: i,
          });
        }
      });
      return client.party.meta.set('Default:RawSquadAssignments_j', {
        RawSquadAssignments: assignments,
      });
  };

  client.party.members.find(member => member.id === id).hidden = true;
  await client.party.sendPatch({
      'Default:RawSquadAssignments_j': client.party.meta.updateSquadAssignments()
  });
}

async function showPlayer(id, client) {
  client.party.members.find(member => member.id === id).hidden = false;
  await client.party.sendPatch({
      'Default:RawSquadAssignments_j': client.party.meta.updateSquadAssignments()
  });
}

(async () => {
  if(!env.DEVICE_ID) {
    const { access_token } = await (await fetch('https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token', {
      method: 'POST',
      body: 'token_type=eg1&grant_type=client_credentials',
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "basic NTIyOWRjZDNhYzM4NDUyMDhiNDk2NjQ5MDkyZjI1MWI6ZTNiZDJkM2UtYmY4Yy00ODU3LTllN2QtZjNkOTQ3ZDIyMGM3"
      }
    })).json();
    const { device_code, verification_uri_complete } = await (await fetch('https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/deviceAuthorization', {
      method: 'POST',
      body: 'prompt=login',
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": `bearer ${access_token}`
      }
    })).json();
    await new Promise((resolve) => rl.question(`Login at ${verification_uri_complete} , then type anything here and press enter.`, async () => {
      const checkDevice_code = async (device_code) => {
        return await (await fetch('https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token', {
          method: 'POST',
          body: `grant_type=device_code&device_code=${device_code}`,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "basic NTIyOWRjZDNhYzM4NDUyMDhiNDk2NjQ5MDkyZjI1MWI6ZTNiZDJkM2UtYmY4Yy00ODU3LTllN2QtZjNkOTQ3ZDIyMGM3"
          }
        })).json();
      }
      const authorization = await checkDevice_code(device_code);
      if(authorization.error) {
        console.log('s');
        return rl.close();
      }
      const { code } = await (await fetch('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/exchange', {
          headers: {
            "Content-Type": "application/json",
            "Authorization": `bearer ${authorization.access_token}`
          }
      })).json();
      const { account_id, access_token: token } = await (await fetch('https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token', {
        method: 'POST',
        body: `grant_type=exchange_code&exchange_code=${code}&token_type=eg1`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "basic MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE="
        }
      })).json();
      const { deviceId: device_id, secret } = await (await fetch(`https://account-public-service-prod.ol.epicgames.com/account/api/public/account/${account_id}/deviceAuth`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `bearer ${token}`
        }
      })).json();
      const discordAuth = await new Promise((resolve) => rl.question(`Please go to https://webfort.herokuapp.com/api/user and copy and paste the id of your account here.`, resolve));
      console.log(`Copy this into the .env file\n\nDEVICE_ID=${device_id}\nACCOUNT_ID=${account_id}\nSECRET=${secret}\nAUTH_DISCORD=${discordAuth}\n\nThen restart.`);
      resolve();
      rl.close();
    }));
    return;
  }
  app.listen(process.env.PORT || 3000, () => console.log(`[BOT] Listening to http://localhost:${process.env.PORT || 3000}/`));

  app.post('/api/account', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const sessiondf = sessions.find(session => session.user === user.id);
    if(sessiondf)
      return res.status(403).send({
        statusCode: 403,
        error: 'webfort.fortnite.auth.already',
        message: 'You have already authorized.'
      });

    const AuthorizeMethod = {
      account_id: env.ACCOUNT_ID,
      device_id: env.DEVICE_ID,
      secret: env.SECRET
    };
    const client = new Client({
      auth: {
        deviceAuth: AuthorizeMethod
      }
    });
    sessions.push({
      client,
      user: user.id,
      AuthorizeMethod,
      res: null
    });
    
    res.sendStatus(200);
  });

  app.get('/api/account/authorize', async (req, res) => {
    if(!accountsSessions[req.query.auth]) return throwError(res, 401);
    const user = accountsSessions[req.query.auth].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401);

    const client = session.client;
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.flushHeaders();
    sessions.find(session => session.user === user.id).res = res;
    client.debug = (data) => {
      const session = sessions.find(session => session.user === user.id);
      if(data.startsWith('XMPP-Client successfully connected ') && queues[user.id]) {
        queues[user.id] = {
          queue: 'login',
          completed: true
        }
        if(!res.writableEnded) res.write(`data: ${JSON.stringify({ completed: true })}\n\n`);
      }
      if(session && session.res && !session.res.writableEnded) {
        session.res.write(`data: ${JSON.stringify({ message: data, completed: false })}\n\n`);
      }
    }
    setEvents(client, res);

    res.once('close', async () => {
      return res.end();
    });
    if(queues[user.id] && queues[user.id].queue === 'logout') {
      res.write(`data: ${JSON.stringify({ message: 'Waiting to logout first.', completed: false })}\n\n`);
      await new Promise((resolve) => {
        const inv = setInterval(() => {
          if(!queues[user.id]) {
            resolve();
            clearInterval(inv);
          }
        });
      });
    }
    if(queues[user.id] && queues[user.id].queue === 'login' && queues[user.id].completed === true) {
      res.write(`data: ${JSON.stringify({ completed: true })}\n\n`);
    }
    else {
      if(queues[user.id] && queues[user.id].queue === 'login' && queues[user.id].completed === false) {
        res.write(`data: ${JSON.stringify({ message: 'Waiting for login to finish.', completed: false })}\n\n`);
        await new Promise((resolve) => {
          const inv = setInterval(() => {
            if(!queues[user.id]) clearInterval(inv);
            if(queues[user.id].queue === 'login' && queues[user.id].completed === true) resolve();
          });
        });
        res.write(`data: ${JSON.stringify({ completed: true })}\n\n`);
      }
      else if(!queues[user.id]) {
        queues[user.id] = {
          queue: 'login',
          completed: false
        }
        await client.login();
        queues[user.id] = {
          queue: 'login',
          completed: true
        }
      }
    }
    setTimeout(async () => {
      if(sessions.find(session => session.user === user.id).res && !sessions.find(session => session.user === user.id).res.writableEnded) {
        sessions.find(session => session.user === user.id).res.write(`data: ${JSON.stringify({exit: true})}\n\n`);
      }
      queues[user.id] = {
        queue: 'logout',
        done: false
      }
      sessions = sessions.filter(e => e.user !== user.id);
      await session.client.logout();
      delete queues[user.id];
    }, 3600000);
  });

  app.get('/api/account', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401);
    if(Object.keys({...session.client.user}).length === 0) return throwError(res, 401, 'You\'re not fully authorized yet!');
    res.send({
      ...session.client.user
    });
  });

  app.get('/api/accounts', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const AuthorizeMethods = getNonUsedAuths();
    const response = {
      auth: AuthorizeMethods.length !== 0,
      accounts: []
    }
    if(AuthorizeMethods.length !== 0) {
      for (const account of AuthorizeMethods) {
        response.accounts.push(account.displayName);
      }
    }
    res.send(response);
  });

  app.delete('/api/account/', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    if(session.res && !session.res.writableEnded) session.res.write(`data: ${JSON.stringify({ exit: true })}\n\n`);
    queues[user.id] = {
      queue: 'logout',
      done: false
    }
    sessions = sessions.filter(e => e.user !== user.id);
    await session.client.logout();
    delete queues[user.id];
    res.send(204);
  });

  app.get('/api/auth/', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    res.send({ auth: req.headers['set-cookie'][0].split('auth=')[1] });
  });

  app.put('/api/account/meta', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    const client = session.client;
    const operation = req.body.operation;
    if(!operation) return throwError(res, 403, 'operation is needed.');
    switch(operation) {
      case 'cosmetic': {
        const type = req.body.type;
        const args = req.body.arguments;
        if(!type) return throwError(res, 403, 'type is needed.');
        if(!args) return throwError(res, 403, 'arguments is needed.');
        try {
          await client.party.me[`set${type.charAt(0).toUpperCase() + type.slice(1)}`](...args);
        } catch(err) {
          return res.status(403).send(err);
        }
        res.send(204);
      } break;

      default: {
        throwError(res, 403, 'Operation is invalid.');
      } break;
    }
  });

  app.get('/api/account/party/kick', async (req, res) => {
    if(!req.query.id) return throwError(res, 400);
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const id = req.query.id;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Session not found.');
    const client = session.client;
    const member = client.party.members.find(m => m.id === id);
    if(!member) return throwError(res, 404, 'Member not found.');
    await member.kick();
    res.sendStatus(200);
  });

  app.post('/api/account/party/member', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    const client = session.client;
    const operation = req.body.operation;
    const id = req.query.id;
    if(!operation) return throwError(res, 403, 'operation is needed.');
    if(!id) return throwError(res, 403, 'id of member is needed.');
    if(!client.party.members.find(m => m.id === id)) return throwError(res, 404, 'Member not found.');
    switch(operation) {
      case 'hide': {
        try {
          await hidePlayer(id, client);
        } catch(err) {
          return res.status(403).send(err);
        }
        res.send(204);
      } break;

      case 'show': {
        try {
          await showPlayer(id, client);
        } catch(err) {
          return res.status(403).send(err);
        }
        res.send(204);
      } break;

      default: {
        throwError(res, 403, 'Operation is invalid.');
      } break;
    }
  });

  app.get('/api/account/party/member/hide', async (req, res) => {
    if(!req.query.id) return throwError(res, 400);
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const id = req.query.id;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Session not found.');
    const client = session.client;
    const member = client.party.members.find(m => m.id === id);
    if(!member) return throwError(res, 404, 'Member not found.');
    await hidePlayer(member.id, client);
    res.sendStatus(200);
  });

  app.get('/api/account/party/member/show', async (req, res) => {
    if(!req.query.id) return throwError(res, 400);
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const id = req.query.id;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Session not found.');
    const client = session.client;
    const member = client.party.members.find(m => m.id === id);
    if(!member) return throwError(res, 404, 'Member not found.');
    await showPlayer(member.id, client);
    res.sendStatus(200);
  });

  function setEvents(client, res) {
    async function getParty() {
      const members = [];
      for (const mapValue of client.party.members) {
        let member = mapValue[1];
        if(!member.displayName) member.displayName = (await client.getProfile(member.id)).displayName;
        members.push({
          ...member,
          meta: gets(member.meta.schema)
        });
      }
      return ({
        ...client.party,
        members,
        meta: gets(client.party.meta.schema)
      });
    }
    client.on('friend:request', async (req) => {
      await req.accept();
    });
      client.on('party:member:joined', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
        res.write(`data: ${JSON.stringify({ event: 'party:member:joined', data: req })}\n\n`);
      }
    });
    client.on('party:updated', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
      }
    });
    client.on('party:member:disconnected', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
      }
    });
    client.on('friend:message', async (message) => {
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'friend:message', data: {
          content: message.content,
          author: {
            id: message.author.id,
            displayName: message.author.displayName
          },
          sentAt: new Date().toISOString()
        }})}\n\n`);
      }
    });
    client.on('party:member:message', async (message) => {
      console.log(message);
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'party:message', data: message })}\n\n`);
      }
    });
    client.on('party:invite', async (e) => {
      try {
        await e.accept();
      } catch(s) {}
    });
    client.on('party:member:kicked', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
        res.write(`data: ${JSON.stringify({ event: 'party:member:kicked', data: req })}\n\n`);
      }
    });
    client.on('party:member:expired', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
      }
    });
    client.on('party:member:left', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
        res.write(`data: ${JSON.stringify({ event: 'party:member:left', data: req })}\n\n`);
      }
    });
    client.on('party:member:updated', async (req) => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      if(!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ event: 'refresh:party', party: await getParty(), data: req })}\n\n`);
      }
    });
  }

  function gets(value) {
    const data = {};
    for (const key of Object.keys(value)) {
      let input = value[key];
      try {
        JSON.parse(input);
      } catch(error) {
        data[key] = input;
        continue;
      }
      input = gets(JSON.parse(input));
      data[key] = input;
    }
    return data;
  }

  app.get('/api/account/party', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    const client = session.client;
    const members = [];
    if(!client.party.members) return throwError(res, 401, 'You\'re not fully authorized yet!');
    for (const mapValue of client.party.members) {
      let member = mapValue[1];
      if(!member.displayName) member.displayName = (await client.getProfile(member.id)).displayName;
      members.push({
        ...member,
        meta: gets(member.meta.schema)
      });
    }
    res.send({
      ...client.party,
      members,
      meta: gets(client.party.meta.schema)
    });
  });

  app.get('/api/account/friends', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    const client = session.client;
    const friends = [];
    for (const friendO of client.friends.toArray()) {
      const friend = friendO[Object.keys(friendO)[0]];
      friends.push({
        displayName: friend.displayName,
        id: friend.id,
        presence: {
          status: friend.presence ? friend.presence.status : null
        }
      });
    }
    res.send(friends);
  });

  app.post('/api/account/party', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    const client = session.client;
    const operation = req.body.operation;
    if(!operation) return throwError(res, 403, 'operation is needed.');
    switch(operation) {
      case 'leave': {
        try {
          await client.party.leave();
        } catch(err) {
          return res.status(403).send(err);
        }
        res.send(204);
      } break;

      case 'join': {
        const type = req.body.type;
        const id = req.body.id;
        if(!type) return throwError(res, 403, 'type is needed.');
        if(!id) return throwError(res, 403, 'id is needed.');
        switch(type) {
          case 'friend': {
            const friend = client.friends.toArray().find(e => e[Object.keys(e)[0]].id === id)[Object.keys(client.friends.toArray().find(e => e[Object.keys(e)[0]].id === id))[0]];
            if(!friend) return throwError(res, 400);
            try {
              await friend.joinParty();
            } catch(err) {
              return res.status(403).send(err);
            }
            res.send(204);
          } break;

          default: {
            throwError(res, 403, 'type is invalid.');
          } break;
        }
        try {
          await client.party.leave();
        } catch(err) {
          return res.status(403).send(err);
        }
        res.send(204);
      } break;

      default: {
        throwError(res, 403, 'Operation is invalid.');
      } break;
    }
  });
  
  app.get('/api/account/fn/content', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    if(!session) return throwError(res, 401, 'Create a session first!');
    res.send(await (await fetch('https://fortnitecontent-website-prod07.ol.epicgames.com/content/api/pages/fortnite-game')).json());
  });

  app.post('/api/account/friends/send', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    const friend = req.query.id;
    const message = req.query.message;
    if(!friend || !message) return throwError(res, 400);
    if(!session || !session.client) return throwError(res, 401);
    const client = session.client;
    client.sendFriendMessage(friend, message);
    res.sendStatus(204);
  });

  app.post('/api/account/party/send', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    const message = req.query.message;
    if(!message) return throwError(res, 400);
    if(!session || !session.client) return throwError(res, 401);
    const client = session.client;
    client.party.sendMessage(message);
    res.sendStatus(204);
  });

  app.post('/api/account/friends/remove', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    const friend = req.query.id;
    if(!friend) return throwError(res, 400);
    if(!session || !session.client) return throwError(res, 401);
    const client = session.client;
    await client.removeFriend(friend);
    res.sendStatus(204);
  });

  app.post('/api/account/friends/invite', async (req, res) => {
    if(!accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]]) return throwError(res, 401);
    const user = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]].user;
    const session = sessions.find(session => session.user === user.id);
    const friend = req.query.id;
    if(!friend)  return throwError(res, 400);
    if(!session || !session.client) return throwError(res, 401);
    const client = session.client;
    await client.invite(friend);
    res.sendStatus(204);
  });

  app.get('/api/user', async (req, res) => {
    const auth = accountsSessions[req.headers['set-cookie'][0].split('auth=')[1]];
    if(!accountsSessions[auth]) return res.send({ authorization: false });
    res.send({...accountsSessions[auth].user});
  });

})();