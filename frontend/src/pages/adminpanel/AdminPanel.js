import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../../context/AuthContext';
import './AdminPanel.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const StatCard = ({ label, value, sub, color }) => (
    <div className="admin-stat-card glass-panel">
        <p className="admin-stat-label">{label}</p>
        <h2 className="admin-stat-value" style={{ color }}>{value}</h2>
        {sub && <p className="admin-stat-sub">{sub}</p>}
    </div>
);

const AdminPanel = () => {
    const [users, setUsers] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterRole, setFilterRole] = useState('all');
    const [sortBy, setSortBy] = useState('date_joined');
    const [sortDir, setSortDir] = useState('desc');

    const { tokens, logout } = useAuth();

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await axios.get(`${API_URL}/api/admin/users/`, {
                    headers: { Authorization: `Bearer ${tokens?.access}` }
                });
                // Defensive: handle both {users:[...]} and [...] shapes
                const data = response.data;
                const userList = Array.isArray(data)
                    ? data
                    : Array.isArray(data?.users)
                    ? data.users
                    : [];
                setUsers(userList);
            } catch (err) {
                console.error('AdminPanel fetch error:', err);
                if (err.response?.status === 401 || err.response?.status === 403) {
                    setError('Access Denied — insufficient clearance level.');
                } else {
                    setError('Unable to reach user registry. Is the backend running?');
                }
            } finally {
                setIsLoading(false);
            }
        };
        if (tokens?.access) fetchUsers();
        else setIsLoading(false);
    }, [tokens]);

    // ── Computed stats (safe) ──
    const safeUsers = Array.isArray(users) ? users : [];
    const totalUsers    = safeUsers.length;
    const regularUsers  = safeUsers.filter(u => !u.is_staff).length;
    const adminUsers    = safeUsers.filter(u => u.is_staff).length;
    const totalScans    = safeUsers.reduce((acc, u) => acc + (u.total_scans || 0), 0);
    const totalPhishing = safeUsers.reduce((acc, u) => acc + (u.phishing_count || 0), 0);

    // ── Filter + sort ──
    const filtered = safeUsers
        .filter(u => {
            const q = searchQuery.toLowerCase();
            const uname = (u.username || '').toLowerCase();
            const email = (u.email || '').toLowerCase();
            const matchSearch = uname.includes(q) || email.includes(q);
            const matchRole =
                filterRole === 'all' ? true :
                filterRole === 'admin' ? !!u.is_staff : !u.is_staff;
            return matchSearch && matchRole;
        })
        .sort((a, b) => {
            let av = a[sortBy] ?? '';
            let bv = b[sortBy] ?? '';
            if (sortBy === 'username') { av = av.toString().toLowerCase(); bv = bv.toString().toLowerCase(); }
            if (sortBy === 'date_joined') { av = new Date(av); bv = new Date(bv); }
            if (av < bv) return sortDir === 'asc' ? -1 : 1;
            if (av > bv) return sortDir === 'asc' ? 1 : -1;
            return 0;
        });

    const toggleSort = (col) => {
        if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
        else { setSortBy(col); setSortDir('desc'); }
    };

    const SortIcon = ({ col }) => (
        sortBy === col
            ? <span style={{ color: 'var(--accent-cyan)', marginLeft: 4 }}>{sortDir === 'asc' ? '↑' : '↓'}</span>
            : <span style={{ opacity: 0.25, marginLeft: 4 }}>↕</span>
    );

    const fmtDate = (iso) => {
        if (!iso) return '—';
        const d = new Date(iso);
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    };

    const fmtDateTime = (iso) => {
        if (!iso) return 'Never';
        try {
            return new Date(iso).toLocaleString('en-IN', {
                day: '2-digit', month: 'short', year: 'numeric',
                hour: '2-digit', minute: '2-digit'
            });
        } catch { return '—'; }
    };

    // ── Loading ──
    if (isLoading) {
        return (
            <div className="admin-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
                <div className="spinner mb-4" style={{ width: '60px', height: '60px', borderTopColor: 'var(--accent-purple)' }}></div>
                <p className="text-muted text-uppercase tracking-widest" style={{ letterSpacing: '0.2em', fontSize: '0.85rem' }}>
                    Loading User Registry...
                </p>
            </div>
        );
    }

    // ── Error ──
    if (error) {
        return (
            <div className="admin-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '60vh' }}>
                <div className="glass-panel text-center p-5" style={{ maxWidth: '500px', borderColor: 'var(--accent-rose)' }}>
                    <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔒</div>
                    <h4 className="text-rose text-uppercase tracking-widest mb-3">ACCESS DENIED</h4>
                    <p className="text-muted mb-4">{error}</p>
                    <button className="cyber-btn cyber-btn-primary" onClick={logout}>LOGOUT</button>
                </div>
            </div>
        );
    }

    return (
        <div className="admin-container pb-5">

            {/* ── Header ── */}
            <div className="admin-header mb-5">
                <div>
                    <h2 className="admin-title mb-1">
                        ADMIN <span style={{ color: 'var(--accent-cyan)' }}>DASHBOARD</span>
                    </h2>
                    <p className="text-muted text-uppercase tracking-widest mb-0" style={{ fontSize: '0.8rem' }}>
                        Registered User Management
                    </p>
                </div>
                <div className="d-flex gap-2 align-items-center flex-wrap">
                    <span className="cyber-badge cyan">Superuser Access</span>
                    <span className="cyber-badge info">{totalUsers} Total Users</span>
                </div>
            </div>

            {/* ── Stat Cards ── */}
            <div className="admin-stats-grid mb-5">
                <StatCard label="Total Registered"  value={totalUsers}    sub="All accounts"          color="var(--accent-cyan)" />
                <StatCard label="Regular Users"      value={regularUsers}  sub="Non-admin accounts"    color="var(--accent-cyan)" />
                <StatCard label="Admins"             value={adminUsers}    sub="Staff accounts"        color="var(--accent-cyan)" />
                <StatCard label="Total Scans"        value={totalScans}    sub="Across all users"      color="var(--accent-cyan)" />
                <StatCard label="Phishing Detected"  value={totalPhishing} sub="Total threats flagged" color="var(--accent-rose)" />
            </div>

            {/* ── Filters ── */}
            <div className="glass-panel p-0 overflow-hidden">
                <div className="admin-filters p-4 border-bottom" style={{ borderColor: 'var(--separator)' }}>
                    <input
                        type="text"
                        className="cyber-input admin-search"
                        placeholder="Search by username or email..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        style={{ border: '1px solid rgba(0,240,255,0.25)', background: 'rgba(0,240,255,0.03)' }}
                    />
                    <div className="admin-filter-pills">
                        {['all', 'admin', 'user'].map(r => (
                            <button
                                key={r}
                                onClick={() => setFilterRole(r)}
                                className={`filter-pill ${filterRole === r ? 'active' : ''}`}
                            >
                                {r === 'all' ? 'All Users' : r === 'admin' ? 'Admins Only' : 'Users Only'}
                            </button>
                        ))}
                    </div>
                    <span className="text-muted" style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                        {filtered.length} of {totalUsers} shown
                    </span>
                </div>

                {/* ── Table ── */}
                <div className="table-responsive">
                    <table className="admin-table w-100 m-0">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th className="sortable" onClick={() => toggleSort('username')}>
                                    Username <SortIcon col="username" />
                                </th>
                                <th>Email</th>
                                <th>Role</th>
                                <th className="sortable" onClick={() => toggleSort('date_joined')}>
                                    Joined <SortIcon col="date_joined" />
                                </th>
                                <th className="sortable" onClick={() => toggleSort('total_scans')}>
                                    Scans <SortIcon col="total_scans" />
                                </th>
                                <th>Phishing</th>
                                <th>Legitimate</th>
                                <th>Suspicious</th>
                                <th>Last Activity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.length > 0 ? (
                                filtered.map((user, idx) => (
                                    <tr key={user.id}>
                                        <td className="text-muted" style={{ fontSize: '0.8rem', fontFamily: 'monospace' }}>
                                            {String(idx + 1).padStart(2, '0')}
                                        </td>
                                        <td>
                                            <div className="d-flex align-items-center gap-2">
                                                <div className="user-avatar" style={{
                                                    background: user.is_staff ? 'rgba(138,43,226,0.2)' : 'rgba(0,255,255,0.1)',
                                                    color: user.is_staff ? 'var(--accent-purple)' : 'var(--accent-cyan)'
                                                }}>
                                                    {(user.username || '?').charAt(0).toUpperCase()}
                                                </div>
                                                <span className="text-main fw-bold" style={{ fontFamily: 'monospace' }}>
                                                    {user.username || '—'}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="text-muted" style={{ fontSize: '0.88rem' }}>{user.email || '—'}</td>
                                        <td>
                                            <span className={`cyber-badge ${user.is_staff ? 'purple' : 'info'}`} style={{ fontSize: '0.65rem' }}>
                                                {user.is_staff ? '⭐ ADMIN' : '👤 USER'}
                                            </span>
                                        </td>
                                        <td className="text-muted" style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>
                                            {fmtDate(user.date_joined)}
                                        </td>
                                        <td>
                                            <span className="text-cyan fw-bold">{user.total_scans ?? 0}</span>
                                        </td>
                                        <td>
                                            <span className={(user.phishing_count || 0) > 0 ? 'text-rose fw-bold' : 'text-muted'}>
                                                {(user.phishing_count || 0) > 0 ? `🔴 ${user.phishing_count}` : 0}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={(user.legitimate_count || 0) > 0 ? 'text-emerald' : 'text-muted'}>
                                                {(user.legitimate_count || 0) > 0 ? `🟢 ${user.legitimate_count}` : 0}
                                            </span>
                                        </td>
                                        <td style={(user.suspicious_count || 0) > 0 ? { color: 'var(--accent-gold)' } : {}}>
                                            <span className={(user.suspicious_count || 0) === 0 ? 'text-muted' : ''}>
                                                {(user.suspicious_count || 0) > 0 ? `🟡 ${user.suspicious_count}` : 0}
                                            </span>
                                        </td>
                                        <td className="text-muted" style={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>
                                            {fmtDateTime(user.last_scan_date)}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="10" className="text-center p-5 text-muted">
                                        <div style={{ fontSize: '2.5rem', marginBottom: '0.75rem', opacity: 0.4 }}>👤</div>
                                        <p className="text-uppercase tracking-widest mb-0" style={{ fontSize: '0.8rem' }}>
                                            {searchQuery ? 'No users match your search' : 'No users registered yet'}
                                        </p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default AdminPanel;
