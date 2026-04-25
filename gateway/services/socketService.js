let io;

module.exports = {
  init: (httpServer) => {
    // allow cors so dashboard can connect
    io = require('socket.io')(httpServer, {
      cors: {
        origin: '*', // for demo purposes
      }
    });
    return io;
  },
  getIo: () => {
    return io;
  }
};
