const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Функция загрузки на ImgBB
async function uploadToImgBB(env, b64) {
  if (!b64) return null;
  try {
    const base64Data = b64.includes(',') ? b64.split(',')[1] : b64;
    const formData = new FormData();
    formData.append('image', base64Data);

    const res = await fetch(`https://api.imgbb.com/1/upload?key=${env.IMGBB_API_KEY}`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    return data.success ? data.data.url : null;
  } catch (e) { return null; }
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });
    
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '');
    
    // Supabase настройки
    const sbHeaders = { 
      'apikey': env.SUPABASE_SERVICE_KEY, 
      'Authorization': 'Bearer ' + env.SUPABASE_SERVICE_KEY, 
      'Content-Type': 'application/json',
      'Prefer': 'return=representation'
    };

    let body = {};
    if (request.method === 'POST' || request.method === 'PATCH') {
      try { body = await request.json(); } catch(e) {}
    }

    // 1. Посты (Создание)
    if (path === '/posts' && request.method === 'POST') {
      let imageUrl = await uploadToImgBB(env, body.image_base64);
      const res = await fetch(`${env.SUPABASE_URL}/rest/v1/posts`, {
        method: 'POST',
        headers: sbHeaders,
        body: JSON.stringify({
          user_id: body.user_id, // или из JWT если настроено
          text: body.text,
          image_url: imageUrl
        })
      });
      return new Response(JSON.stringify(await res.json()), { headers: corsHeaders });
    }

    // 2. Аватарки (Профиль)
    if (path === '/profile' && request.method === 'PATCH') {
      let avatarUrl = body.avatar_base64 ? await uploadToImgBB(env, body.avatar_base64) : null;
      const updateData = { ...body };
      if (avatarUrl) updateData.avatar = avatarUrl;
      delete updateData.avatar_base64;

      const res = await fetch(`${env.SUPABASE_URL}/rest/v1/users?id=eq.${body.id}`, {
        method: 'PATCH',
        headers: sbHeaders,
        body: JSON.stringify(updateData)
      });
      return new Response(JSON.stringify(await res.json()), { headers: corsHeaders });
    }

    // Универсальный аплоад (для тестов)
    if (path === '/upload' && request.method === 'POST') {
      const link = await uploadToImgBB(env, body.file_base64);
      return new Response(JSON.stringify({ url: link }), { headers: corsHeaders });
    }

    return new Response('Not Found', { status: 404 });
  }
};
