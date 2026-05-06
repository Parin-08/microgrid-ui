import { jsxRenderer } from 'hono/jsx-renderer'

export const renderer = jsxRenderer(({ children }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>CyberSecure Microgrid Controller</title>
        <link rel="icon" type="image/svg+xml" href="/static/favicon.svg" />
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet" />
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <link href="/static/style.css" rel="stylesheet" />
      </head>
      <body>
        <div id="app-root"></div>
        <script src="/static/app.js"></script>
      </body>
    </html>
  )
})
