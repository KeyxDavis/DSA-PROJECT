// src/App.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = 'http://localhost:3000';

function App() {
  const [token, setToken] = useState('');
  const [mentors, setMentors] = useState([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const login = async () => {
    try {
      const res = await axios.post(`${API_URL}/auth/login`, { email, password });
      setToken(res.data.token);
    } catch (e) {
      alert('Login failed');
    }
  };

  const fetchMentors = async () => {
    if (!token) return;
    // For demo, fetch all mentors (you need to implement this endpoint in backend)
    const res = await axios.get(`${API_URL}/users?role=mentor`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    setMentors(res.data);
  };

  useEffect(() => {
    fetchMentors();
  }, [token]);

  if (!token) {
    return (
      <div>
        <h2>Login</h2>
        <input placeholder="Email" onChange={e => setEmail(e.target.value)} />
        <input placeholder="Password" type="password" onChange={e => setPassword(e.target.value)} />
        <button onClick={login}>Login</button>
      </div>
    );
  }

  return (
    <div>
      <h2>Mentors</h2>
      <ul>
        {mentors.map(m => (
          <li key={m.id}>{m.name} - {m.skills?.join(', ')}</li>
        ))}
      </ul>
    </div>
  );
}

export default App;
// Note: This is a very basic example. In a real application, you would want to handle errors, loading states, and possibly use a more sophisticated state management solution like Redux or Context API.