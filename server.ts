/**
 * Bun Server for Password Hashing
 * Provides API endpoints for Argon2 and Bcrypt hashing
 */

const PORT = 3001;

const server = Bun.serve({
    port: PORT,
    async fetch(req) {
        const url = new URL(req.url);

        // CORS headers
        const headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Content-Type': 'application/json',
        };

        // Handle preflight
        if (req.method === 'OPTIONS') {
            return new Response(null, { headers });
        }

        // Argon2 hashing endpoint
        if (url.pathname === '/api/hash/argon2' && req.method === 'POST') {
            try {
                const { password } = await req.json();

                if (!password) {
                    return new Response(
                        JSON.stringify({ error: 'Password is required' }),
                        { status: 400, headers }
                    );
                }

                const hash = await Bun.password.hash(password, {
                    algorithm: 'argon2id',
                    timeCost: 3,
                    memoryCost: 65536, // 64 MiB
                });

                return new Response(
                    JSON.stringify({ hash }),
                    { headers }
                );
            } catch (error) {
                return new Response(
                    JSON.stringify({ error: error instanceof Error ? error.message : 'Hashing failed' }),
                    { status: 500, headers }
                );
            }
        }

        // Bcrypt hashing endpoint
        if (url.pathname === '/api/hash/bcrypt' && req.method === 'POST') {
            try {
                const { password } = await req.json();

                if (!password) {
                    return new Response(
                        JSON.stringify({ error: 'Password is required' }),
                        { status: 400, headers }
                    );
                }

                const hash = await Bun.password.hash(password, {
                    algorithm: 'bcrypt',
                    cost: 10,
                });

                return new Response(
                    JSON.stringify({ hash }),
                    { headers }
                );
            } catch (error) {
                return new Response(
                    JSON.stringify({ error: error instanceof Error ? error.message : 'Hashing failed' }),
                    { status: 500, headers }
                );
            }
        }

        // Health check
        if (url.pathname === '/api/health') {
            return new Response(
                JSON.stringify({ status: 'ok', message: 'Hashing server running' }),
                { headers }
            );
        }

        return new Response(
            JSON.stringify({ error: 'Not found' }),
            { status: 404, headers }
        );
    },
});

console.log(`🔐 Hashing API Server running on http://localhost:${PORT}`);
console.log(`   Endpoints:`);
console.log(`   - POST http://localhost:${PORT}/api/hash/argon2`);
console.log(`   - POST http://localhost:${PORT}/api/hash/bcrypt`);
console.log(`   - GET  http://localhost:${PORT}/api/health`);
