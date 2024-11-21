from http.server import SimpleHTTPRequestHandler
import socketserver

class CS144Handler(SimpleHTTPRequestHandler):

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])

PORT = 80

Handler = CS144Handler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("Server1: httpd serving at port", PORT)
    httpd.serve_forever()
