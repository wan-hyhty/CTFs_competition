const fs = require('fs')
const app = require('fastify')()
const crypto = require('crypto')
const md5 = d => crypto.createHash('md5').update(d).digest('hex')
const dbPromisePool = require('mysql2').createPool({
  host: 'mysql',
  user: 'root',
  database: 'local_db',
  password: 'local_password'
}).promise()


// app.setErrorHandler((error, req, resp) => {
//   console.error(`[fastify]`, error)
//   resp.status(503).send({ error: 'Vui lÃ²ng thá»­ láº¡i sau.' })
// })

app.addHook('preHandler', async (req, resp) => {
  resp.status(200).header('Content-Type', 'application/json')
})

app.post('/login', async req => {
  if (req.body.user === 'admin') return;
  const [rows] = await dbPromisePool.query(`select *, bio as flag from users where username = ? and password = ? limit 1`, [req.body.user, req.body.pass])
  return rows[0]
})

app.post('/register', async req => {
  const [rows] = await dbPromisePool.query(`insert users(username, password, bio) values(?, ?, ?)`, [req.body.user, md5(req.body.pass), req.body.bio])
  if (rows.insertId) return String(rows.insertId)
  return { error: 'Lá»—i, vui lÃ²ng thá»­ láº¡i sau' }
})

app.get('/', async (req, resp) => {
  resp.status(200).header('Content-Type', 'text/plain')
  return fs.promises.readFile(__filename)
})

app.listen({ port: 3000, host: '0.0.0.0' }, () => console.log('Running', app.addresses()))