/**
 * Role-Based Access Control Middleware
 * Usage: router.get('/admin/...', requireRole('admin'), handler)
 */
const requireRole = (...allowedRoles) => (req, res, next) => {
  const role = req.user?.role;
  if (!role) return res.status(401).json({ error: 'Unauthorized — authentication required' });
  if (!allowedRoles.includes(role)) {
    return res.status(403).json({
      error: `Forbidden — requires role: [${allowedRoles.join(', ')}]`,
      yourRole: role
    });
  }
  next();
};

module.exports = requireRole;
