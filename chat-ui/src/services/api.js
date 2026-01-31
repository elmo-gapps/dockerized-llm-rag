async function request(path, options = {}, baseUrl = import.meta.env.VITE_API_BASE_URL) {
    const token = localStorage.getItem('token');
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${baseUrl || ''}${path}`, {
        ...options,
        headers,
    });

    if (response.status === 401 && !path.includes('/login')) {
        localStorage.removeItem('token');
        window.location.reload();
    }

    return response;
}

export const api = {
    login: (email, password) =>
        fetch(`${import.meta.env.VITE_AUTH_URL || ''}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        }).then(r => r.json()),

    getSessions: () => request('/api/sessions').then(r => r.json()),

    getSession: (id) => request(`/api/sessions/${id}`).then(r => r.json()),

    chat: (message, sessionId = null) =>
        request('/api/chat', {
            method: 'POST',
            body: JSON.stringify({ message, session_id: sessionId }),
        }),

    deleteSession: (id) => request(`/api/sessions/${id}`, { method: 'DELETE' }),

    // User Management
    listUsers: () => request('/users', {}, import.meta.env.VITE_AUTH_URL).then(r => r.json()),

    createUser: (data) => request('/users', {
        method: 'POST',
        body: JSON.stringify(data)
    }, import.meta.env.VITE_AUTH_URL).then(r => r.json()),

    deleteUser: (email) => request(`/users/${email}`, {
        method: 'DELETE'
    }, import.meta.env.VITE_AUTH_URL).then(r => r.json()),
};
