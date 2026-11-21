// Inert synthetic fixtures, not a runnable application.
// GT: P26 VS-01 vulnerable
const STRIPE_SECRET = 'sk_live_ABCDEFGHIJKLMNOP01234567';
// GT: P27 VS-01 vulnerable
const apiKey = 'AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ012345678';
app.get('/notes', (req, res) => {
  const q = req.query.q;
  // GT: P28 VS-05 vulnerable
  db.query('SELECT * FROM notes WHERE id=' + q);
  // GT: P29 VS-05 vulnerable
  res.send('<p>' + q);
  // GT: P30 VS-05 vulnerable
  child_process.exec('ls ' + q);
  // GT: S16 VS-05 safe
  db.query('SELECT * FROM notes WHERE id=?', [q]);
  // GT: S17 VS-05 safe
  res.json({value: q});
  // GT: S18 VS-05 safe
  child_process.execFile('ls', [q]);
});
// GT: P31 VS-05 vulnerable
const view = <div dangerouslySetInnerHTML={{__html: value}} />;
// GT: P32 VS-05 vulnerable
document.body.innerHTML = location.hash;
// GT: P33 VS-01 vulnerable
const client = createClient(url, 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.synthetic_signature');
// GT: S19 VS-05 safe
const safeView = <div>{value}</div>;
// GT: S20 VS-05 safe
document.body.textContent = location.hash;
// GT: S21 VS-01 safe
const apiKeyExample = 'your-api-key';
