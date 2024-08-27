### This is a multithread HTTP server implemented in C. It is a solution to the CodeCrafters.io challenge to build an HTTP server.

The server is capable of serving multiple clients simultaneously thanks to the POSIX threads library; where each client has its own thread. To avoid memory leaks, the server uses thread pools, memory pools and a linked list to store the data and free it when the execution is done. The server can serve static files, and handles GET and POST requests.

Disclaimer: I am not responsible for any misuse of this code. This code is intended for educational purposes only.

[![progress-banner](https://backend.codecrafters.io/progress/http-server/5c760191-8433-4f7d-88f5-5681f3e20588)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

