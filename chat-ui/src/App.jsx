import React, { useState, useEffect } from 'react';
import { api } from './services/api';
import { cn } from './lib/utils';
import {
  Send,
  Plus,
  MessageSquare,
  LogOut,
  User,
  Bot,
  Trash2,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  ShieldCheck,
  Users,
  UserPlus,
  RefreshCw,
  MoreVertical
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { motion, AnimatePresence } from 'framer-motion';

const parseJwt = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch (e) {
    return null;
  }
};

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(token ? parseJwt(token) : null);
  const [sessions, setSessions] = useState([]);
  const [currentSessionId, setCurrentSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [currentView, setCurrentView] = useState('chat'); // 'chat' or 'admin'

  // Admin state
  const [allUsers, setAllUsers] = useState([]);
  const [isAdminPanelLoading, setIsAdminPanelLoading] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('user');

  // Login state (temporary simple form)
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState('');

  useEffect(() => {
    if (token) {
      loadSessions();
      setUser(parseJwt(token));
    }
  }, [token]);

  const loadSessions = async () => {
    try {
      const data = await api.getSessions();
      setSessions(data);
    } catch (err) {
      console.error('Failed to load sessions');
    }
  };

  const loadUsers = async () => {
    if (user?.role !== 'admin') return;
    setIsAdminPanelLoading(true);
    try {
      const data = await api.listUsers();
      setAllUsers(data);
    } catch (err) {
      console.error('Failed to load users');
    } finally {
      setIsAdminPanelLoading(false);
    }
  };

  useEffect(() => {
    if (currentView === 'admin') {
      loadUsers();
    }
  }, [currentView]);

  useEffect(() => {
    if (currentSessionId) {
      loadMessages(currentSessionId);
    } else {
      setMessages([]);
    }
  }, [currentSessionId]);

  const loadMessages = async (id) => {
    try {
      const data = await api.getSession(id);
      setMessages(data.messages);
    } catch (err) {
      console.error('Failed to load messages');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoginError('');
    try {
      const data = await api.login(email, password);
      if (data.token) {
        localStorage.setItem('token', data.token);
        setToken(data.token);
        const decoded = parseJwt(data.token);
        setUser(decoded);
      } else {
        setLoginError(data.error || 'Login failed');
      }
    } catch (err) {
      setLoginError('Login failed');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setCurrentSessionId(null);
    setMessages([]);
    setCurrentView('chat');
  };

  const handleSend = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMsg = { role: 'user', content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const response = await api.chat(userMsg.content, currentSessionId);

      if (!response.ok) throw new Error('Chat failed');

      if (!currentSessionId) {
        // If it was a new session, reload sessions to get the ID
        const data = await response.json();
        setCurrentSessionId(data.session_id);
        loadSessions();
        setMessages(data.messages);
      } else {
        // Handle streaming or simple JSON
        const data = await response.json();
        setMessages(data.messages);
      }
    } catch (err) {
      console.error(err);
      setMessages(prev => [...prev, { role: 'assistant', content: 'Error: Failed to get response from AI.' }]);
    } finally {
      setLoading(false);
    }
  };

  const deleteSession = async (id, e) => {
    e.stopPropagation();
    if (confirm('Delete this session?')) {
      await api.deleteSession(id);
      if (currentSessionId === id) setCurrentSessionId(null);
      loadSessions();
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      await api.createUser({
        email: newUserEmail,
        password: newUserPassword,
        role: newUserRole
      });
      setNewUserEmail('');
      setNewUserPassword('');
      loadUsers();
    } catch (err) {
      alert('Failed to create user');
    }
  };

  const handleDeleteUser = async (email) => {
    if (confirm(`Are you sure you want to remove user ${email}?`)) {
      try {
        await api.deleteUser(email);
        loadUsers();
      } catch (err) {
        alert('Failed to delete user');
      }
    }
  };

  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-md bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl shadow-2xl p-10 relative overflow-hidden"
        >
          {/* Decorative Background Blob */}
          <div className="absolute -top-24 -right-24 h-48 w-48 bg-accent/20 blur-3xl rounded-full"></div>

          <div className="mb-10 text-center relative">
            <div className="mx-auto w-16 h-16 bg-gradient-to-br from-brand-500 to-accent rounded-2xl flex items-center justify-center shadow-xl shadow-brand-500/20 mb-6 group cursor-default">
              <Bot size={32} className="text-white transform group-hover:rotate-12 transition-transform duration-500" />
            </div>
            <h1 className="text-4xl font-display font-bold bg-clip-text text-transparent bg-gradient-to-b from-white to-white/60">
              Antigravity
            </h1>
            <p className="mt-3 text-brand-300 font-medium tracking-tight">Enterprise Intelligence</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-6 relative">
            <div className="space-y-2">
              <label className="text-sm font-semibold text-brand-200 ml-1">Work Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 focus:outline-none transition-all"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-semibold text-brand-200 ml-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 focus:outline-none transition-all"
                required
              />
            </div>

            {loginError && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="text-sm text-red-400 bg-red-400/10 border border-red-400/20 px-4 py-2 rounded-lg"
              >
                {loginError}
              </motion.div>
            )}

            <button type="submit" className="w-full mt-4 bg-gradient-to-br from-brand-500 to-accent px-6 py-3 rounded-xl font-bold text-white shadow-lg shadow-brand-500/20 hover:shadow-brand-500/40 transition-all active:scale-95">
              Sign In to Environment
            </button>
          </form>

          <p className="mt-8 text-center text-[10px] text-white/30 uppercase tracking-[0.3em] font-black">
            Secure Infrastructure
          </p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <AnimatePresence mode="wait">
        {isSidebarOpen && (
          <motion.div
            initial={{ x: -300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: -300, opacity: 0 }}
            className="flex flex-col w-72 h-full bg-white/5 backdrop-blur-xl border-r border-white/10 relative z-30"
          >
            <div className="p-6 space-y-3">
              <button
                onClick={() => {
                  setCurrentSessionId(null);
                  setCurrentView('chat');
                  if (window.innerWidth < 1024) setIsSidebarOpen(false);
                }}
                className="flex w-full items-center justify-center gap-3 bg-white/5 border border-white/10 hover:bg-white/10 p-4 rounded-2xl transition-all group shadow-lg"
              >
                <Plus size={18} className="text-brand-400 group-hover:scale-125 transition-transform" />
                <span className="font-bold text-sm tracking-tight text-brand-50">New Intelligence</span>
              </button>

              {user?.role === 'admin' && (
                <button
                  onClick={() => {
                    setCurrentView(currentView === 'admin' ? 'chat' : 'admin');
                    if (window.innerWidth < 1024) setIsSidebarOpen(false);
                  }}
                  className={cn(
                    "flex w-full items-center gap-4 p-4 rounded-2xl transition-all border",
                    currentView === 'admin'
                      ? "bg-brand-500/20 border-brand-500/40 text-brand-300"
                      : "bg-white/5 border-white/10 text-white/40 hover:bg-white/10 hover:text-white"
                  )}
                >
                  <ShieldCheck size={18} />
                  <span className="font-bold text-sm tracking-tight">Admin System</span>
                </button>
              )}
            </div>

            <div className="flex-1 overflow-y-auto px-4 custom-scrollbar space-y-1.5 py-4">
              <div className="text-[10px] uppercase tracking-[0.2em] font-black text-white/20 mb-6 px-3">Knowledge Threads</div>
              {sessions.map((s) => (
                <motion.div
                  layout
                  key={s.id}
                  onClick={() => {
                    setCurrentSessionId(s.id);
                    setCurrentView('chat');
                    if (window.innerWidth < 1024) setIsSidebarOpen(false);
                  }}
                  className={cn(
                    "group flex items-center justify-between rounded-xl p-3.5 cursor-pointer transition-all border border-transparent",
                    currentSessionId === s.id && currentView === 'chat'
                      ? "bg-brand-500/10 border-brand-500/30 text-brand-300 shadow-xl shadow-brand-500/5 translate-x-1"
                      : "hover:bg-white/5 text-white/40 hover:text-white"
                  )}
                >
                  <div className="flex items-center gap-3 overflow-hidden">
                    <MessageSquare size={16} className={cn("shrink-0 transition-colors", currentSessionId === s.id && currentView === 'chat' ? "text-brand-400" : "text-white/10")} />
                    <span className="truncate text-sm font-semibold">{s.title || 'Insight Session'}</span>
                  </div>
                  <button
                    onClick={(e) => deleteSession(s.id, e)}
                    className="opacity-0 group-hover:opacity-100 p-2 hover:bg-red-500/10 hover:text-red-400 rounded-lg transition-all"
                  >
                    <Trash2 size={14} />
                  </button>
                </motion.div>
              ))}
            </div>

            <div className="p-4 bg-black/40 backdrop-blur-2xl">
              <div className="flex items-center justify-between bg-white/5 p-4 rounded-2xl border border-white/5 shadow-2xl">
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-brand-500 to-accent flex items-center justify-center shadow-lg shadow-brand-500/20 shrink-0">
                    <User size={18} className="text-white" />
                  </div>
                  <div className="flex flex-col overflow-hidden">
                    <span className="text-sm font-black text-white truncate tracking-tight">{user?.sub?.split('@')[0] || email.split('@')[0]}</span>
                    <span className="text-[10px] text-white/30 truncate font-bold">{user?.sub || email}</span>
                  </div>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2.5 hover:bg-white/10 rounded-xl text-white/20 hover:text-red-400 transition-all active:scale-90"
                >
                  <LogOut size={18} />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Area */}
      {currentView === 'chat' ? (
        <div className="flex flex-1 flex-col overflow-hidden relative bg-[#0a0a0c]">
          {/* Top Gradient */}
          <div className="absolute top-0 left-0 right-0 h-40 bg-gradient-to-b from-brand-500/5 to-transparent pointer-events-none"></div>

          <header className="flex h-24 items-center justify-between px-10 relative z-20">
            <div className="flex items-center gap-6">
              <button
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                className="bg-white/5 backdrop-blur-xl border border-white/10 p-3 rounded-2xl hover:bg-white/10 transition-all active:scale-95 shadow-xl"
              >
                <Menu size={20} className="text-brand-400" />
              </button>
              <div className="space-y-1">
                <h2 className="text-2xl font-display font-bold tracking-tight text-white/90">
                  {currentSessionId ? sessions.find(s => s.id === currentSessionId)?.title || 'Intelligence Thread' : 'New Knowledge Base'}
                </h2>
                <div className="flex items-center gap-2 px-1">
                  <div className="h-1.5 w-1.5 rounded-full bg-brand-500 shadow-[0_0_8px_rgba(var(--brand-500),0.8)] animate-pulse"></div>
                  <span className="text-[10px] uppercase tracking-[0.25em] font-black text-white/20">Neural Engine Online</span>
                </div>
              </div>
            </div>
          </header>

          <div className="flex-1 overflow-y-auto px-10 py-10 custom-scrollbar relative z-10">
            <div className="max-w-4xl mx-auto space-y-12 pb-24">
              {messages.length === 0 ? (
                <motion.div
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="flex flex-col items-center justify-center h-[55vh] text-center"
                >
                  <div className="h-28 w-28 bg-gradient-to-br from-brand-500 to-accent rounded-[2.5rem] flex items-center justify-center shadow-2xl shadow-brand-500/20 mb-10 relative group">
                    <div className="absolute inset-0 bg-brand-500/20 blur-3xl rounded-full group-hover:blur-2xl transition-all duration-700"></div>
                    <Bot size={56} className="text-white relative drop-shadow-2xl" />
                  </div>
                  <h3 className="text-4xl font-display font-bold bg-clip-text text-transparent bg-gradient-to-b from-white to-white/40 leading-tight">
                    Initiate Research Session
                  </h3>
                  <p className="mt-5 text-brand-200/50 max-w-sm text-lg font-medium leading-relaxed italic">
                    "Architecture for a persistent, secure intelligence synthesis layer."
                  </p>
                  <div className="mt-14 flex flex-wrap justify-center gap-3">
                    {['Neural Synthesis', 'Code Engineering', 'Decision Hub'].map(tag => (
                      <span key={tag} className="bg-white/5 border border-white/10 backdrop-blur-md px-5 py-2.5 rounded-2xl text-[10px] font-black uppercase tracking-widest text-white/30 hover:text-brand-400 transition-colors cursor-default">{tag}</span>
                    ))}
                  </div>
                </motion.div>
              ) : (
                <AnimatePresence initial={false}>
                  {messages.map((m, i) => (
                    <motion.div
                      initial={{ opacity: 0, y: 15 }}
                      animate={{ opacity: 1, y: 0 }}
                      key={i}
                      className={cn(
                        "flex gap-8 group",
                        m.role === 'user' ? "flex-row-reverse" : "flex-row"
                      )}
                    >
                      <div className={cn(
                        "h-12 w-12 rounded-2xl flex items-center justify-center shrink-0 shadow-2xl mt-1.5 transition-all duration-500",
                        m.role === 'user' ? "bg-white/5 border border-white/10 text-brand-400 ring-4 ring-white/5" : "bg-gradient-to-br from-brand-500 to-accent text-white shadow-brand-500/20 ring-4 ring-brand-500/10"
                      )}>
                        {m.role === 'user' ? <User size={22} /> : <Bot size={22} />}
                      </div>
                      <div className={cn(
                        "rounded-[2rem] py-1.5 px-1.5 max-w-[82%] relative",
                        m.role === 'user' ? "bg-brand-500/10 border border-brand-500/20 shadow-xl" : ""
                      )}>
                        <div className={cn(
                          "p-6 rounded-[1.8rem]",
                          m.role === 'user' ? "text-brand-100" : "text-white/95"
                        )}>
                          <div className="prose prose-invert max-w-none prose-p:leading-[1.8] prose-pre:bg-black/40 prose-pre:border prose-pre:border-white/10 prose-pre:rounded-2xl prose-code:text-accent prose-code:font-bold prose-headings:font-display prose-headings:text-white pb-2">
                            <ReactMarkdown>{m.content}</ReactMarkdown>
                          </div>
                          <div className="flex items-center gap-3 mt-4 px-1">
                            <div className="h-0.5 flex-1 bg-white/5"></div>
                            <span className="text-[9px] font-black uppercase tracking-widest text-white/20">{m.role === 'user' ? 'Transmission Log' : 'Neural Core Response'}</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}

              {loading && (
                <div className="flex gap-8 px-2">
                  <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-brand-500 to-accent text-white flex items-center justify-center shrink-0 animate-spin-slow">
                    <Bot size={22} />
                  </div>
                  <div className="bg-white/5 border border-white/10 backdrop-blur-xl px-8 py-5 rounded-[2rem] flex items-center gap-4 shadow-2xl">
                    <span className="text-[10px] font-black text-brand-400 uppercase tracking-[0.3em] animate-pulse">Synthesizing Intelligence</span>
                    <div className="flex gap-2">
                      {[0, 150, 300].map(delay => (
                        <div key={delay} className="h-2 w-2 bg-brand-500 rounded-full animate-bounce shadow-[0_0_8px_rgba(var(--brand-500),0.8)]" style={{ animationDelay: `${delay}ms` }}></div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Input Area */}
          <div className="p-10 relative z-20">
            <form
              onSubmit={handleSend}
              className="mx-auto max-w-4xl relative group"
            >
              {/* Ambient Shadow glow */}
              <div className="absolute -inset-1 bg-gradient-to-r from-brand-500/0 via-brand-500/10 to-accent/0 rounded-[2.5rem] blur-2xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-1000"></div>

              <div className="relative bg-white/5 border border-white/10 backdrop-blur-3xl p-3 pl-6 rounded-[2.5rem] min-h-[82px] flex items-end shadow-3xl transition-all duration-500 group-focus-within:border-brand-500/30 group-focus-within:bg-white/8">
                <textarea
                  rows="1"
                  placeholder="Submit synthesis request..."
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value);
                    e.target.style.height = 'auto';
                    e.target.style.height = e.target.scrollHeight + 'px';
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSend(e);
                    }
                  }}
                  disabled={loading}
                  className="flex-1 bg-transparent border-none py-4 text-white placeholder:text-white/20 focus:ring-0 resize-none max-h-60 custom-scrollbar min-h-[50px] font-medium leading-relaxed"
                />
                <button
                  type="submit"
                  disabled={!input.trim() || loading}
                  className="mb-1 ml-4 h-14 w-14 bg-gradient-to-br from-brand-500 to-accent hover:from-brand-400 hover:to-accent disabled:from-white/5 disabled:to-white/5 rounded-[1.5rem] text-white flex items-center justify-center shadow-2xl shadow-brand-500/20 transition-all active:scale-90 group/btn"
                >
                  <Send size={24} className="group-hover/btn:translate-x-1 group-hover/btn:-translate-y-1 transition-transform duration-300" />
                </button>
              </div>

              <div className="mt-6 flex justify-center items-center gap-8">
                <div className="flex items-center gap-2">
                  <div className="h-1 w-1 bg-brand-500 rounded-full"></div>
                  <span className="text-[10px] font-black uppercase tracking-[0.2em] text-white/15">End-to-End Encrypted</span>
                </div>
                <div className="h-1 w-1 bg-white/5 rounded-full"></div>
                <div className="flex items-center gap-2">
                  <div className="h-1 w-1 bg-brand-600 rounded-full"></div>
                  <span className="text-[10px] font-black uppercase tracking-[0.2em] text-white/15">Enterprise Infrastructure</span>
                </div>
              </div>
            </form>
          </div>
        </div>
      ) : (
        <div className="flex flex-1 flex-col overflow-hidden relative bg-[#0a0a0c]">
          {/* Admin Panel View */}
          <div className="absolute top-0 left-0 right-0 h-40 bg-gradient-to-b from-brand-500/5 to-transparent pointer-events-none"></div>

          <header className="flex h-24 items-center justify-between px-10 relative z-20">
            <div className="flex items-center gap-6">
              <button
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                className="bg-white/5 backdrop-blur-xl border border-white/10 p-3 rounded-2xl hover:bg-white/10 transition-all active:scale-95 shadow-xl"
              >
                <Menu size={20} className="text-brand-400" />
              </button>
              <div className="space-y-1">
                <h2 className="text-2xl font-display font-bold tracking-tight text-white/90">Identity Management</h2>
                <div className="flex items-center gap-2 px-1">
                  <ShieldCheck size={12} className="text-brand-500" />
                  <span className="text-[10px] uppercase tracking-[0.25em] font-black text-white/20">Secure Control Plane</span>
                </div>
              </div>
            </div>

            <button
              onClick={loadUsers}
              className="p-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl text-white/40 hover:text-white transition-all shadow-xl"
            >
              <RefreshCw size={18} className={cn(isAdminPanelLoading ? "animate-spin" : "")} />
            </button>
          </header>

          <div className="flex-1 overflow-y-auto px-10 py-10 custom-scrollbar relative z-10">
            <div className="max-w-6xl mx-auto space-y-10">

              {/* Stats / Quick Actions */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white/5 border border-white/10 p-8 rounded-3xl backdrop-blur-xl">
                  <div className="text-[10px] uppercase tracking-widest text-white/20 font-black mb-1">Authenticated Users</div>
                  <div className="text-4xl font-bold font-display text-white">{allUsers.length}</div>
                </div>

                <div className="bg-white/5 border border-white/10 p-8 rounded-3xl backdrop-blur-xl md:col-span-2">
                  <div className="text-[10px] uppercase tracking-widest text-white/20 font-black mb-4">Provision New Identity</div>
                  <form onSubmit={handleCreateUser} className="flex flex-col md:flex-row gap-4">
                    <input
                      type="email"
                      placeholder="User Email"
                      value={newUserEmail}
                      onChange={(e) => setNewUserEmail(e.target.value)}
                      required
                      className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 outline-none"
                    />
                    <input
                      type="password"
                      placeholder="Initial Password"
                      value={newUserPassword}
                      onChange={(e) => setNewUserPassword(e.target.value)}
                      required
                      className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 outline-none"
                    />
                    <select
                      value={newUserRole}
                      onChange={(e) => setNewUserRole(e.target.value)}
                      className="bg-white/5 border border-white/10 rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-brand-500/50 text-white/60"
                    >
                      <option value="user" className="bg-[#1a1a1c]">User</option>
                      <option value="admin" className="bg-[#1a1a1c]">Admin</option>
                    </select>
                    <button type="submit" className="bg-brand-500 hover:bg-brand-400 text-white px-6 py-3 rounded-xl font-bold flex items-center gap-2 shadow-lg shadow-brand-500/20 active:scale-95 transition-all">
                      <UserPlus size={18} />
                      <span>Provision</span>
                    </button>
                  </form>
                </div>
              </div>

              {/* User List */}
              <div className="bg-white/5 border border-white/10 rounded-3xl backdrop-blur-xl overflow-hidden shadow-2xl">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-white/5 bg-white/2">
                      <th className="px-8 py-6 text-[10px] font-black uppercase tracking-widest text-white/20">Identity</th>
                      <th className="px-8 py-6 text-[10px] font-black uppercase tracking-widest text-white/20">Access Role</th>
                      <th className="px-8 py-6 text-[10px] font-black uppercase tracking-widest text-white/20 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {allUsers.map((u) => (
                      <tr key={u.email} className="group hover:bg-white/[0.02] transition-colors">
                        <td className="px-8 py-6">
                          <div className="flex items-center gap-4">
                            <div className="h-10 w-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-brand-400 group-hover:scale-110 transition-transform">
                              <User size={18} />
                            </div>
                            <span className="font-bold text-white/80">{u.email}</span>
                          </div>
                        </td>
                        <td className="px-8 py-6">
                          <span className={cn(
                            "px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest leading-none",
                            u.role === 'admin' ? "bg-brand-500/10 text-brand-400 border border-brand-500/20" : "bg-white/5 text-white/40 border border-white/10"
                          )}>
                            {u.role}
                          </span>
                        </td>
                        <td className="px-8 py-6 text-right">
                          <button
                            onClick={() => handleDeleteUser(u.email)}
                            disabled={u.email === user?.sub}
                            className="p-2.5 rounded-xl hover:bg-red-500/10 text-white/10 hover:text-red-400 transition-all disabled:opacity-0"
                          >
                            <Trash2 size={18} />
                          </button>
                        </td>
                      </tr>
                    ))}
                    {allUsers.length === 0 && (
                      <tr>
                        <td colSpan="3" className="px-8 py-20 text-center text-white/20 font-medium italic">
                          No identity transmissions detected in current environment.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
