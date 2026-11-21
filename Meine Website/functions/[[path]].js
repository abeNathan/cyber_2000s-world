
async function sign(value, secret) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(value)
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

async function validSession(request, secret) {
    const cookies = request.headers.get("Cookie") || "";
    const match = cookies.match(/access_session=([^;]+)/);

    if (!match) return false;

    const parts = match[1].split(".");
    if (parts.length !== 2) return false;

    const [expiry, signature] = parts;

    if (!/^\d+$/.test(expiry)) return false;
    if (Number(expiry) < Math.floor(Date.now() / 1000)) return false;

    return signature === await sign(expiry, secret);
}

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/login" && request.method === "POST") {
        const form = await request.formData();
        const code = form.get("code");

        if (typeof code !== "string" || code !== env.ACCESS_CODE) {
            return new Response("Falscher Zugangscode.", {
                status: 401
            });
        }

        const expiry = String(
            Math.floor(Date.now() / 1000) + 86400
        );

        const signature = await sign(expiry, env.SESSION_SECRET);

        return new Response(null, {
            status: 303,
            headers: {
                "Location": "/world.html",
                "Set-Cookie": `access_session=${expiry}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
            }
        });
    }

    const protectedPages = [
    "/world.html",
    "/world",
    "/about.html",
    "/about"
];

    if (protectedPages.includes(path)) {
        const valid = await validSession(request, env.SESSION_SECRET);

        if (!valid) {
            return Response.redirect(url.origin + "/login.html", 302);
        }
    }

    return context.next();
}
