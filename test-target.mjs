// هدف اختبار محلي آمن — لاختبار الفاحص ضده
import http from 'node:http';
http.createServer((rq, rs) => {
  if (rq.url === '/.env') { rs.writeHead(200, { 'Content-Type': 'text/plain' }); return rs.end('DB_PASSWORD=supersecret123\nAPI_KEY=abc-def-ghi'); }
  if (rq.url === '/admin/') { rs.writeHead(200, { 'Content-Type': 'text/html' }); return rs.end('<html><head><title>Admin Panel</title></head><body>Login</body></html>'); }
  if (rq.url === '/uploads/') { rs.writeHead(200, { 'Content-Type': 'text/html' }); return rs.end('<html><head><title>Index of /uploads/</title></head><body>files here</body></html>'); }
  if (rq.url === '/api/v1/users') { rs.writeHead(200, { 'Content-Type': 'application/json' }); return rs.end(JSON.stringify({ users: [{ id: 1, name: 'test' }] })); }
  if (rq.url === '/swagger.json') { rs.writeHead(200, { 'Content-Type': 'application/json' }); return rs.end(JSON.stringify({ openapi: '3.0.0', info: { title: 'Test API' } })); }
  rs.writeHead(200, { 'Content-Type': 'text/html', 'Server': 'nginx/1.18.0', 'X-Powered-By': 'Express' });
  rs.end('<html><head><title>Test Site</title></head><body><meta name="generator" content="WordPress 5.8">Welcome</body></html>');
}).listen(8099, '127.0.0.1', () => console.log('test target ready → http://127.0.0.1:8099'));
