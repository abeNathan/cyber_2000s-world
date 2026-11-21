async function sign(value, secret) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function validSession(request, secret) {
    if (!secret) return false;
    const cookies = request.headers.get("Cookie") || "";
    const match = cookies.match(/access_session=([^;]+)/);
    if (!match) return false;
    const parts = match[1].split(".");
    if (parts.length !== 2) return false;
    const [expiry, signature] = parts;
    if (!/^\d+$/.test(expiry) || Number(expiry) < Math.floor(Date.now() / 1000)) return false;
    return signature === await sign(expiry, secret);
}

async function validAdminSession(request, secret) {
    if (!secret) return false;
    const cookies = request.headers.get("Cookie") || "";
    const match = cookies.match(/admin_session=([^;]+)/);
    if (!match) return false;
    const parts = match[1].split(".");
    if (parts.length !== 2) return false;
    const [expiry, signature] = parts;
    if (!/^\d+$/.test(expiry) || Number(expiry) < Math.floor(Date.now() / 1000)) return false;
    return signature === await sign("admin:" + expiry, secret);
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
    });
}

async function diaryApi(request, env, path) {
    if (!env.GALLERY_BUCKET) return json({ error: "Speicher ist noch nicht verbunden." }, 503);
    const prefix = "diary/";
    if (path === "/api/diary" && request.method === "GET") {
        const listed = await env.GALLERY_BUCKET.list({ prefix, limit: 100 });
        const entries = [];
        for (const object of listed.objects) {
            const stored = await env.GALLERY_BUCKET.get(object.key);
            if (!stored) continue;
            try {
                const entry = await stored.json();
                entries.push(entry);
            } catch {}
        }
        entries.sort((a, b) => String(b.date).localeCompare(String(a.date)) || String(b.id).localeCompare(String(a.id)));
        return json({ entries });
    }
    if (!await validAdminSession(request, env.SESSION_SECRET)) {
        return json({ error: "Admin-Anmeldung erforderlich." }, 403);
    }
    if (path === "/api/diary" && request.method === "POST") {
        let body;
        try { body = await request.json(); } catch { return json({ error: "Ungültige Anfrage." }, 400); }
        const title = typeof body?.title === "string" ? body.title.trim().slice(0, 60) : "";
        const date = typeof body?.date === "string" ? body.date : "";
        const text = typeof body?.text === "string" ? body.text.trim().slice(0, 3000) : "";
        if (!title || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !text) return json({ error: "Bitte Titel, Datum und Text ausfüllen." }, 400);
        const id = crypto.randomUUID();
        const entry = { id, title, date, text };
        await env.GALLERY_BUCKET.put(prefix + id + ".json", JSON.stringify(entry), {
            httpMetadata: { contentType: "application/json; charset=utf-8" }
        });
        return json({ entry }, 201);
    }
    if (path === "/api/diary" && request.method === "DELETE") {
        let body;
        try { body = await request.json(); } catch { return json({ error: "Ungültige Anfrage." }, 400); }
        const id = typeof body?.id === "string" ? body.id : "";
        if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Ungültige Eintrags-ID." }, 400);
        await env.GALLERY_BUCKET.delete(prefix + id + ".json");
        return json({ deleted: true });
    }
    return new Response("Method not allowed", { status: 405 });
}

async function galleryApi(request, env, path) {
    if (!env.GALLERY_BUCKET) return json({ error: "Die Galerie ist noch nicht vollständig verbunden." }, 503);

    if (path === "/api/gallery" && request.method === "GET") {
        const listed = await env.GALLERY_BUCKET.list({ prefix: "photos/", limit: 200 });
        const photos = await Promise.all(listed.objects.map(async object => {
            const stored = await env.GALLERY_BUCKET.get(object.key);
            return {
                key: object.key,
                uploaded: object.uploaded ? object.uploaded.toISOString() : null,
                caption: stored && stored.customMetadata ? (stored.customMetadata.caption || "") : ""
            };
        }));
        photos.reverse();
        return json({ photos });
    }

    if (path.startsWith("/api/gallery/") && request.method === "GET") {
        const key = decodeURIComponent(path.slice("/api/gallery/".length));
        if (!key.startsWith("photos/") || key.includes("..")) return new Response("Not found", { status: 404 });
        const object = await env.GALLERY_BUCKET.get(key);
        if (!object) return new Response("Not found", { status: 404 });
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set("Cache-Control", "private, max-age=300");
        headers.set("X-Content-Type-Options", "nosniff");
        return new Response(object.body, { headers });
    }

    if (path === "/api/gallery" && request.method === "POST") {
        if (!await validAdminSession(request, env.SESSION_SECRET)) {
            return json({ error: "Admin-Anmeldung erforderlich." }, 403);
        }
        const form = await request.formData();
        const files = form.getAll("photos").filter(value => value instanceof File);
        const captions = form.getAll("captions").filter(value => typeof value === "string").map(value => value.slice(0, 240));
        if (!files.length || files.length > 6) return json({ error: "Bitte 1 bis 6 Bilder auswählen." }, 400);
        const allowed = new Map([["image/jpeg", "jpg"], ["image/png", "png"], ["image/webp", "webp"], ["image/gif", "gif"]]);
        const uploaded = [];
        for (const file of files) {
            if (!allowed.has(file.type) || file.size > 5 * 1024 * 1024 || file.size === 0) {
                return json({ error: "Nur JPG, PNG, WEBP oder GIF bis 5 MB pro Bild sind erlaubt." }, 400);
            }
        }
        for (const [index, file] of files.entries()) {
            const key = "photos/" + crypto.randomUUID() + "." + allowed.get(file.type);
            await env.GALLERY_BUCKET.put(key, file.stream(), {
                httpMetadata: { contentType: file.type, cacheControl: "private, max-age=300" },
                customMetadata: {
                    originalName: file.name.slice(0, 120),
                    caption: (captions[index] || "").trim()
                }
            });
            uploaded.push(key);
        }
        return json({ uploaded });
    }

    if (path === "/api/gallery" && request.method === "PATCH") {
        if (!await validAdminSession(request, env.SESSION_SECRET)) {
            return json({ error: "Admin-Anmeldung erforderlich." }, 403);
        }
        let body;
        try {
            body = await request.json();
        } catch {
            return json({ error: "Ungültige Anfrage." }, 400);
        }
        const key = body && typeof body.key === "string" ? body.key : "";
        const caption = body && typeof body.caption === "string" ? body.caption.trim().slice(0, 240) : "";
        if (!/^photos\/[0-9a-f-]{36}\.(jpg|png|webp|gif)$/i.test(key)) {
            return json({ error: "Ungültiger Foto-Schlüssel." }, 400);
        }
        const existing = await env.GALLERY_BUCKET.get(key);
        if (!existing) return json({ error: "Foto nicht gefunden." }, 404);
        const headers = new Headers();
        existing.writeHttpMetadata(headers);
        await env.GALLERY_BUCKET.put(key, await existing.arrayBuffer(), {
            httpMetadata: headers,
            customMetadata: {
                ...(existing.customMetadata || {}),
                caption
            }
        });
        return json({ updated: true });
    }

    if (path === "/api/gallery" && request.method === "DELETE") {
        if (!await validAdminSession(request, env.SESSION_SECRET)) {
            return json({ error: "Admin-Anmeldung erforderlich." }, 403);
        }
        let body;
        try {
            body = await request.json();
        } catch {
            return json({ error: "Ungültige Anfrage." }, 400);
        }
        const key = body && typeof body.key === "string" ? body.key : "";
        if (!/^photos\/[0-9a-f-]{36}\.(jpg|png|webp|gif)$/i.test(key)) {
            return json({ error: "Ungültiger Foto-Schlüssel." }, 400);
        }
        await env.GALLERY_BUCKET.delete(key);
        return json({ deleted: true });
    }

    return new Response("Method not allowed", { status: 405 });
}

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/admin/login" && request.method === "POST") {
        const form = await request.formData();
        const secret = form.get("secret");
        if (typeof secret !== "string" || !env.GALLERY_ADMIN_SECRET || secret !== env.GALLERY_ADMIN_SECRET) {
            return json({ error: "Admin-Schlüssel stimmt nicht." }, 403);
        }
        const expiry = String(Math.floor(Date.now() / 1000) + 86400);
        const signature = await sign("admin:" + expiry, env.SESSION_SECRET);
        return new Response(JSON.stringify({ ok: true }), {
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "Set-Cookie": `admin_session=${expiry}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
            }
        });
    }
    if (path === "/admin/logout" && request.method === "POST") {
        return new Response(JSON.stringify({ ok: true }), {
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "Set-Cookie": "admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
            }
        });
    }
    if (path === "/api/admin/session" && request.method === "GET") {
        return json({ isAdmin: await validAdminSession(request, env.SESSION_SECRET) });
    }

    if (path === "/login" && request.method === "POST") {
        const form = await request.formData();
        const code = form.get("code");
        if (typeof code !== "string" || code !== env.ACCESS_CODE) {
            return new Response("Falscher Zugangscode.", { status: 401 });
        }
        const expiry = String(Math.floor(Date.now() / 1000) + 86400);
        const signature = await sign(expiry, env.SESSION_SECRET);
        return new Response(null, {
            status: 303,
            headers: {
                "Location": "/world.html",
                "Set-Cookie": `access_session=${expiry}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
            }
        });
    }

    const protectedPages = ["/world.html", "/world", "/about.html", "/about"];
    const isDiaryApi = path === "/api/diary";
    const isGalleryApi = path === "/api/gallery" || path.startsWith("/api/gallery/");
    if (protectedPages.includes(path) || isGalleryApi || isDiaryApi) {
        const valid = await validSession(request, env.SESSION_SECRET);
        if (!valid) {
            if (isGalleryApi || isDiaryApi) return json({ error: "Bitte zuerst anmelden." }, 401);
            return Response.redirect(url.origin + "/login.html", 302);
        }
    }

    if (isDiaryApi) return diaryApi(request, env, path);
    if (isGalleryApi) return galleryApi(request, env, path);
    return context.next();
}
