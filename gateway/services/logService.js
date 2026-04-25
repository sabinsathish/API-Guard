// Thin in-memory log cache — mirrors what's in MongoDB for fast dashboard reads
const cache = [];
const MAX   = 200;

module.exports = {
  push: (entry) => {
    cache.unshift(entry);
    if (cache.length > MAX) cache.pop();
  },
  getRecent: (n = 100) => cache.slice(0, n)
};
