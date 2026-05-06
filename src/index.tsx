import { Hono } from 'hono'
import { renderer } from './renderer'
import { serveStatic } from 'hono/cloudflare-workers'

const app = new Hono()

app.use(renderer)
app.use('/static/*', serveStatic({ root: './public' }))

app.get('/', (c) => {
  return c.render(<></>)
})

export default app
