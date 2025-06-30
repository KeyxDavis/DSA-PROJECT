const MentorshipRequest = sequelize.define('MentorshipRequest', {
  status: { type: DataTypes.ENUM('pending', 'accepted', 'rejected'), defaultValue: 'pending' },
});

const Session = sequelize.define('Session', {
  scheduledTime: DataTypes.DATE,
  feedback: DataTypes.TEXT,
  rating: DataTypes.INTEGER,
});

// Associations
User.hasMany(MentorshipRequest, { as: 'SentRequests', foreignKey: 'menteeId' });
User.hasMany(MentorshipRequest, { as: 'ReceivedRequests', foreignKey: 'mentorId' });
MentorshipRequest.belongsTo(User, { as: 'Mentee', foreignKey: 'menteeId' });
MentorshipRequest.belongsTo(User, { as: 'Mentor', foreignKey: 'mentorId' });

MentorshipRequest.hasOne(Session);
Session.belongsTo(MentorshipRequest);

sequelize.sync({ alter: true });

// Mentee sends mentorship request
app.post('/requests', authenticateJWT, authorizeRoles('mentee'), async (req, res) => {
  const { mentorId } = req.body;
  if (!mentorId) return res.status(400).json({ error: 'mentorId required' });

  const existing = await MentorshipRequest.findOne({
    where: { menteeId: req.user.id, mentorId, status: 'pending' }
  });
  if (existing) return res.status(400).json({ error: 'Request already pending' });

  const request = await MentorshipRequest.create({ menteeId: req.user.id, mentorId });
  res.status(201).json(request);
});

// Mentor views incoming requests
app.get('/requests/received', authenticateJWT, authorizeRoles('mentor'), async (req, res) => {
  const requests = await MentorshipRequest.findAll({
    where: { mentorId: req.user.id, status: 'pending' },
    include: [{ model: User, as: 'Mentee', attributes: ['id', 'name', 'email'] }]
  });
  res.json(requests);
});

// Mentor accepts/rejects request
app.put('/requests/:id', authenticateJWT, authorizeRoles('mentor'), async (req, res) => {
  const { status } = req.body; // expected 'accepted' or 'rejected'
  if (!['accepted', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });

  const request = await MentorshipRequest.findByPk(req.params.id);
  if (!request || request.mentorId !== req.user.id) return res.sendStatus(404);

  request.status = status;
  await request.save();

  res.json(request);
});
// Mentee views their requests