// === 工作时间表可视化应用 - Cloudflare Worker ===

// --- 后端设定 ---
const PASSWORD = "mjj";                  // 密码
const ALLOWED_COUNTRIES = ["HK", "TW", "CN"];   // 允许香港、台湾和中国大陆 IP
const COOKIE_NAME = "mjj_session_token";      // Cookie 名称
const MAX_LOGIN_ATTEMPTS = 3;             // 最大尝试次数
const LOCKOUT_DURATION = 24 * 60 * 60;    // 锁定时间（秒）- 24小时
const APP_PATH = "/mjj";                 // 应用路径保护层
const MAX_BACKUP_COUNT = 100;             // 最多保留 100 个备份
const KV_NAMESPACE = "SCHEDULE_KV";       // KV 命名空间名称

// --- 主要处理函数 ---
export default {
  async fetch(request, env) {
    // --- 强制使用 HTTPS ---
    const url = new URL(request.url);
    if (url.protocol === "http:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }

    // --- 地区验证 ---
    if (ALLOWED_COUNTRIES !== null) {  // ✅ 只有在 ALLOWED_COUNTRIES 不是 null 時才檢查
      const country = request.cf ? request.cf.country : null;
      if (country && !ALLOWED_COUNTRIES.includes(country)) {
        return new Response(`Access Denied`, { status: 403 });
      }
    }

    // --- 路由处理 ---
    // 0. 根路径提供简单的空白页面
    if (url.pathname === '/') {
      return new Response(`<!DOCTYPE html>
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>页面不存在</title>
            <style>body{font-family:sans-serif;text-align:center;padding:50px;}</style>
          </head>
          <body>
            <h1>404 - 找不到页面</h1>
            <p>请检查您的网址是否正确。</p>
          </body>
        </html>`, {
        headers: { 'Content-Type': 'text/html;charset=utf-8' },
      });
    }

    // 检查请求是否针对受保护的应用路径
    if (url.pathname.startsWith(APP_PATH)) {
      // 1. 处理登入请求
      if (url.pathname === `${APP_PATH}/api/login` && request.method === 'POST') {
        const clientIP = getClientIP(request);
        return await handleLogin(request, env, clientIP);
      }
      
      // 2. 验证身份
      const cookie = request.headers.get('Cookie');
      const isAuthenticated = await checkAuth(cookie, env);

      // 3. 处理主应用页面请求
      if (url.pathname === APP_PATH || url.pathname === `${APP_PATH}/`) {
        return new Response(getHtmlTemplate(APP_PATH), {
          headers: { 'Content-Type': 'text/html;charset=utf-8' },
        });
      }

      // 4. 处理需要验证的 API 请求
      if (url.pathname.startsWith(`${APP_PATH}/api/`)) {
        if (!isAuthenticated) {
          return new Response(JSON.stringify({ error: 'Unauthorized' }), { 
            status: 401, 
            headers: { 'Content-Type': 'application/json' } 
          });
        }
        
        // 已验证，处理行程 API
        if (url.pathname === `${APP_PATH}/api/schedule`) {
          if (request.method === 'GET') {
            const savedData = await env[KV_NAMESPACE].get("schedule_data", { type: "json" });
            return new Response(JSON.stringify(savedData || {}), { 
              headers: { 'Content-Type': 'application/json' } 
            });
          }
          if (request.method === 'POST') {
            const rawText = await request.text();
            const events = parseFreeformText(rawText);
            const dataToStore = { rawText, events };
            
            // 储存到主要资料
            await env[KV_NAMESPACE].put("schedule_data", JSON.stringify(dataToStore));
            
            // 储存到备份历史
            await saveBackup(env, dataToStore);
            
            return new Response(JSON.stringify({ message: '行程已成功储存！' }), { 
              status: 200, 
              headers: { 'Content-Type': 'application/json' } 
            });
          }
        }
        
        // 新增：取得备份列表
        if (url.pathname === `${APP_PATH}/api/backups` && request.method === 'GET') {
          const backups = await getBackupList(env);
          return new Response(JSON.stringify(backups), { 
            headers: { 'Content-Type': 'application/json' } 
          });
        }
        
        // 新增：还原特定备份
        if (url.pathname === `${APP_PATH}/api/restore` && request.method === 'POST') {
          const { backupId } = await request.json();
          const backupData = await env[KV_NAMESPACE].get(`backup:${backupId}`, { type: "json" });
          
          if (!backupData) {
            return new Response(JSON.stringify({ error: '找不到该备份' }), { 
              status: 404, 
              headers: { 'Content-Type': 'application/json' } 
            });
          }
          
          // 还原备份到主要资料
          await env[KV_NAMESPACE].put("schedule_data", JSON.stringify(backupData.data));
          
          return new Response(JSON.stringify({ 
            message: '备份已成功还原！',
            data: backupData.data 
          }), { 
            status: 200, 
            headers: { 'Content-Type': 'application/json' } 
          });
        }
      }
    }
    
    // 5. 404 页面
    return new Response(`<!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>页面不存在</title>
        <style>body{font-family:sans-serif;text-align:center;padding:50px;}</style>
      </head>
      <body>
        <h1>404 - 找不到页面</h1>
        <p>请检查您的网址是否正确。</p>
      </body>
    </html>`, { 
      status: 404,
      headers: { 'Content-Type': 'text/html;charset=utf-8' }
    });
  },
};

// --- 获取客户端 IP ---
function getClientIP(request) {
  const cfIP = request.headers.get('CF-Connecting-IP');
  if (cfIP) return cfIP;
  
  const forwardedFor = request.headers.get('X-Forwarded-For');
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }
  
  return 'unknown-ip';
}

// --- 处理登入逻辑 ---
async function handleLogin(request, env, clientIP) {
  try {
    // 检查 IP 是否被锁定
    const ipLockKey = `login_lock:${clientIP}`;
    const lockData = await env[KV_NAMESPACE].get(ipLockKey, { type: "json" });
    
    if (lockData && lockData.locked) {
      const now = Math.floor(Date.now() / 1000);
      const lockExpiry = lockData.timestamp + LOCKOUT_DURATION;
      
      if (now < lockExpiry) {
        // 计算剩馀锁定时间
        const remainingHours = Math.floor((lockExpiry - now) / 3600);
        const remainingMinutes = Math.floor(((lockExpiry - now) % 3600) / 60);
        return new Response(JSON.stringify({ 
          error: `此 IP 已被锁定。请在 ${remainingHours} 小时 ${remainingMinutes} 分钟后再试。` 
        }), { 
          status: 403, 
          headers: { 'Content-Type': 'application/json' } 
        });
      } else {
        // 锁定已过期，移除锁定
        await env[KV_NAMESPACE].delete(ipLockKey);
      }
    }
    
    // 读取失败尝试计数
    const attemptsKey = `login_attempts:${clientIP}`;
    let attempts = await env[KV_NAMESPACE].get(attemptsKey, { type: "json" }) || { count: 0 };
    
    // 处理登入
    const { password } = await request.json();
    if (password === PASSWORD) {
      const token = crypto.randomUUID();
      const expiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 天后过期
      
      await env[KV_NAMESPACE].put(token, "valid", { expiration: Math.floor(expiry.getTime() / 1000) });
      
      // 登入成功，重设尝试计数
      await env[KV_NAMESPACE].delete(attemptsKey);

      const headers = new Headers();
      headers.append('Set-Cookie', `${COOKIE_NAME}=${token}; Expires=${expiry.toUTCString()}; Path=/; HttpOnly; Secure; SameSite=Strict`);
      
      return new Response(JSON.stringify({ success: true }), { headers });
    } else {
      // 登入失败，增加尝试计数
      attempts.count += 1;
      attempts.timestamp = Math.floor(Date.now() / 1000);
      
      // 储存更新后的尝试计数
      await env[KV_NAMESPACE].put(attemptsKey, JSON.stringify(attempts), { expirationTtl: 24 * 60 * 60 }); // 24小时后过期
      
      // 如果达到最大尝试次数，锁定 IP
      if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        const lockInfo = {
          locked: true,
          timestamp: Math.floor(Date.now() / 1000)
        };
        await env[KV_NAMESPACE].put(ipLockKey, JSON.stringify(lockInfo), { expirationTtl: LOCKOUT_DURATION });
        
        return new Response(JSON.stringify({ 
          error: `密码错误次数过多。您的 IP 已被锁定 ${LOCKOUT_DURATION / 3600} 小时。` 
        }), { 
          status: 403,  
          headers: { 'Content-Type': 'application/json' } 
        });
      }
      
      const remainingAttempts = MAX_LOGIN_ATTEMPTS - attempts.count;
      return new Response(JSON.stringify({ 
        error: `密码错误，您还有 ${remainingAttempts} 次尝试机会。` 
      }), { 
        status: 401, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }
  } catch (e) {
    console.error(e);
    return new Response('请求格式错误', { status: 400 });
  }
}

// --- 验证 Cookie ---
async function checkAuth(cookieHeader, env) {
  if (!cookieHeader) return false;
  const cookies = cookieHeader.split(';');
  const sessionCookie = cookies.find(c => c.trim().startsWith(`${COOKIE_NAME}=`));
  
  if (!sessionCookie) return false;

  const token = sessionCookie.split('=')[1];
  if (!token) return false;
  
  const storedToken = await env[KV_NAMESPACE].get(token);
  return storedToken === "valid";
}

// --- 备份相关函数 ---
async function saveBackup(env, data) {
  const timestamp = Date.now();
  const backupId = `${timestamp}`;
  
  // 储存新备份
  const backupData = {
    id: backupId,
    timestamp: timestamp,
    date: new Date(timestamp).toLocaleString('zh-HK', { 
      timeZone: 'Asia/Hong_Kong',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }),
    data: data,
    preview: data.rawText ? data.rawText.substring(0, 100) + '...' : ''
  };
  
  await env[KV_NAMESPACE].put(`backup:${backupId}`, JSON.stringify(backupData));
  
  // 更新备份索引
  let backupIndex = await env[KV_NAMESPACE].get("backup_index", { type: "json" }) || [];
  backupIndex.unshift(backupId); // 新备份加到最前面
  
  // 保留最新的 100 个备份
  if (backupIndex.length > MAX_BACKUP_COUNT) {
    const toDelete = backupIndex.slice(MAX_BACKUP_COUNT);
    for (const id of toDelete) {
      await env[KV_NAMESPACE].delete(`backup:${id}`);
    }
    backupIndex = backupIndex.slice(0, MAX_BACKUP_COUNT);
  }
  
  await env[KV_NAMESPACE].put("backup_index", JSON.stringify(backupIndex));
}

async function getBackupList(env) {
  const backupIndex = await env[KV_NAMESPACE].get("backup_index", { type: "json" }) || [];
  const backups = [];
  
  for (const id of backupIndex) {
    const backup = await env[KV_NAMESPACE].get(`backup:${id}`, { type: "json" });
    if (backup) {
      backups.push({
        id: backup.id,
        date: backup.date,
        preview: backup.preview
      });
    }
  }
  
  return backups;
}

// --- 行程解析函数 ---
// 修改行程解析函数，为相同个案分配相同颜色

// --- 行程解析函数 ---
function parseFreeformText(textContent) {
  const events = [];
  const currentYear = new Date().getFullYear();
  
  // 修改过滤逻辑：排除空行、以 -- 开头、以 // 开头、以 # 开头的行
  const lines = textContent.trim().split('\n').filter(line => {
    const trimmed = line.trim();
    return trimmed !== '' && 
           !trimmed.startsWith('--') && 
           !trimmed.startsWith('//') && 
           !trimmed.startsWith('#');
  });
  
  const colors = [
    '#007bff',  // 1. 蓝色
    '#fd7e14',  // 2. 橙色
    '#28a745',  // 3. 绿色
    '#dc3545',  // 4. 红色
    '#6f42c1',  // 5. 紫色
    '#17a2b8',  // 6. 青色
    '#ffc107',  // 7. 黄色
    '#e83e8c',  // 8. 粉红色
    '#20c997',  // 9. 青绿色
    '#6610f2',  // 10. 靛蓝色
    '#795548',  // 11. 棕色
    '#198754',  // 12. 深绿色
    '#0dcaf0',  // 13. 浅青色
    '#d63384',  // 14. 深粉红色
    '#6c757d',  // 15. 灰色
    '#0d6efd',  // 16. 亮蓝色
    '#ff5722',  // 17. 深橘红色
    '#9c27b0',  // 18. 深紫罗兰
    '#00bcd4',  // 19. 天蓝色
    '#ff9800'   // 20. 深黄色
  ];

  // 建立个案名称到颜色的映射
  const caseColorMap = {};
  let colorIndex = 0;

  lines.forEach((line, index) => {
    const parts = line.split(/[|｜,，]/);
    if (parts.length >= 4) {
      const [dateStr, timeStr, caseName, ...detailsParts] = parts.map(p => p.trim());
      const details = detailsParts.join(' | ');
      
      // 为新个案分配颜色
      if (!caseColorMap[caseName]) {
        caseColorMap[caseName] = colors[colorIndex % colors.length];
        colorIndex++;
      }
      
      // 支持两种日期格式：
      // 1. 新格式：2025年10月10日
      // 2. 旧格式：10月10日
      let dateMatch = dateStr.match(/(\d{4})年(\d+)月(\d+)日/); // 新格式 (含年份)
      let year, month, day;
      
      if (dateMatch) {
        // 新格式：有年份
        year = parseInt(dateMatch[1], 10);
        month = parseInt(dateMatch[2], 10) - 1; // JavaScript 月份从 0 开始
        day = parseInt(dateMatch[3], 10);
      } else {
        // 尝试旧格式：无年份
        dateMatch = dateStr.match(/(\d+)月(\d+)日/);
        if (dateMatch) {
          year = currentYear; // 使用当前年份
          month = parseInt(dateMatch[1], 10) - 1;
          day = parseInt(dateMatch[2], 10);
        }
      }
      
      // 支持两种时间格式：
      // 1. 时间范围：17:00 - 19:45
      // 2. 单一时间：13:30
      let timeMatch = timeStr.match(/(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})/); // 时间范围
      let startHour, startMinute, endHour, endMinute;
      
      if (timeMatch) {
        // 时间范围格式
        [, startHour, startMinute, endHour, endMinute] = timeMatch;
      } else {
        // 尝试单一时间格式
        const singleTimeMatch = timeStr.match(/(\d{1,2}):(\d{2})/);
        if (singleTimeMatch) {
          [, startHour, startMinute] = singleTimeMatch;
          // 预设结束时间为开始时间 + 2 小时
          const startTime = new Date(year, month, day, parseInt(startHour, 10), parseInt(startMinute, 10));
          const endTime = new Date(startTime.getTime() + 2 * 60 * 60 * 1000); // 加 2 小时
          endHour = endTime.getHours().toString();
          endMinute = endTime.getMinutes().toString().padStart(2, '0');
        }
      }

      if (dateMatch && (timeMatch || timeStr.match(/(\d{1,2}):(\d{2})/)) && caseName) {
        const startDate = new Date(year, month, day, parseInt(startHour, 10), parseInt(startMinute, 10));
        const endDate = new Date(year, month, day, parseInt(endHour, 10), parseInt(endMinute, 10));

        events.push({
          id: `event-${Date.now()}-${index}`,
          title: `个案：${caseName}`,
          start: formatToLocalISO(startDate),
          end: formatToLocalISO(endDate),
          extendedProps: { 
            details: details,
            originalDate: dateStr,
            originalTime: timeStr,
            caseName: caseName  // 保存个案名称以便辨识
          },
          color: caseColorMap[caseName],  // 使用映射的颜色
          display: 'block'
        });
      }
    }
  });
  return events;
}

// --- 日期格式化工具 ---
function formatToLocalISO(date) {
  const pad = (num) => num.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
         `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

// --- 前端 HTML 与 JavaScript ---
function getHtmlTemplate(basePath) {
  return `
<!DOCTYPE html>
<html lang="zh-HK">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>工作时间表可视化 - Nodeseek</title>
  <style>
    /* --- 基本变数与设置 --- */
    :root {
      --primary-color: #007bff;
      --success-color: #28a745;
      --danger-color: #dc3545;
      --light-bg: #f4f7f6;
      --border-radius: 8px;
      --spacing-xs: 5px;
      --spacing-sm: 10px;
      --spacing-md: 15px;
      --spacing-lg: 20px;
      --font-size-sm: 0.875rem;
      --font-size-base: 1rem;
      --font-size-lg: 1.25rem;
      --font-size-xl: 1.5rem;
      --shadow: 0 4px 6px rgba(0,0,0,0.1);
      
      /* 日曆专用变数 */
      --fc-font-size: var(--font-size-base);
      --fc-button-font-size: 0.9em;
      --fc-border-color: #ddd;
    }

    /* --- 基础元素样式 --- */
    * {
      box-sizing: border-box;
      -webkit-tap-highlight-color: transparent;
    }
    
    html {
      height: -webkit-fill-available;
    }
    
    body { 
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
      margin: 0; 
      padding: var(--spacing-sm); 
      background-color: var(--light-bg); 
      -webkit-text-size-adjust: 100%;
      min-height: 100vh;
      min-height: -webkit-fill-available;
      line-height: 1.5;
      color: #333;
    }
    
    /* --- 容器样式 --- */
    .container { 
      width: 100%;
      max-width: 1200px; 
      margin: 0 auto; 
      background: white; 
      padding: var(--spacing-md);
      border-radius: var(--border-radius); 
      box-shadow: var(--shadow); 
    }
    
    /* --- 状态类 --- */
    .hidden { display: none !important; }
    
    /* --- 版面元素样式 --- */
    h1 { 
      font-size: var(--font-size-xl);
      color: #333; 
      margin-top: 0;
      margin-bottom: var(--spacing-md);
      line-height: 1.2;
    }
    
    h2 { 
      font-size: var(--font-size-lg); 
      margin-top: var(--spacing-md);
      margin-bottom: var(--spacing-sm);
      line-height: 1.2;
    }
    
    p {
      margin-top: 0;
      margin-bottom: var(--spacing-sm);
    }
    
    code {
      background-color: #f0f0f0;
      padding: 2px 4px;
      border-radius: 4px;
      font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9em;
    }
    
    /* --- 格式化提示样式 --- */
    .format-hint {
      background-color: #e3f2fd;
      border: 1px solid #90caf9;
      border-radius: var(--border-radius);
      padding: var(--spacing-md);
      margin-bottom: var(--spacing-md);
      font-size: var(--font-size-sm);
      color: #1565c0;
    }

    .format-example {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      background-color: #f5f5f5;
      padding: var(--spacing-xs);
      border-radius: 4px;
      margin: var(--spacing-xs) 0;
      display: block;
      font-size: 0.85em;
    }
    
    /* --- 表单元素样式 --- */
    input[type="password"] { 
      width: 100%; 
      padding: 12px; 
      margin-bottom: var(--spacing-md); 
      border: 1px solid #ccc; 
      border-radius: var(--border-radius); 
      font-size: 16px;
      appearance: none;
      -webkit-appearance: none;
    }
    
    input:focus, textarea:focus {
      outline: none;
      border-color: var(--primary-color);
      box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
    }
    
    /* --- 改善 textarea 样式 --- */
    textarea { 
      width: 100%; 
      height: 650px;
      padding: var(--spacing-md);
      border: 1px solid #ccc; 
      border-radius: var(--border-radius); 
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 13px;
      margin-bottom: var(--spacing-md); 
      resize: vertical;
      line-height: 1.6;
      background-color: #fafafa;
      white-space: pre-wrap;
      tab-size: 4;
    }

    /* --- 工具按钮样式 --- */
    .tool-buttons {
      margin-bottom: var(--spacing-sm);
      display: flex;
      flex-wrap: wrap;
      gap: var(--spacing-xs);
    }

    .tool-button {
      background-color: #6c757d;
      color: white;
      border: none;
      padding: 8px 12px;
      border-radius: var(--border-radius);
      cursor: pointer;
      font-size: 14px;
      transition: background-color 0.2s ease;
      width: auto;
      margin: 0;
    }

    .tool-button:hover {
      background-color: #5a6268;
    }

    .tool-button.clear {
      background-color: var(--danger-color);
    }

    .tool-button.clear:hover {
      background-color: #c82333;
    }
    
    button { 
      color: white; 
      border: none; 
      padding: 12px 18px; 
      border-radius: var(--border-radius); 
      cursor: pointer; 
      font-size: 16px; 
      width: 100%; 
      transition: background-color 0.2s ease;
      font-weight: 500;
      margin-bottom: var(--spacing-sm);
      -webkit-appearance: none;
    }
    
    #saveButton { 
      background-color: var(--success-color);
    }
    
    #saveButton:hover, #saveButton:focus { 
      background-color: #218838; 
    }
    
    #loginButton { 
      background-color: var(--primary-color);
    }
    
    #loginButton:hover, #loginButton:focus { 
      background-color: #0056b3; 
    }
    
    /* --- 状态讯息 --- */
    #status, #login-status { 
      margin: var(--spacing-sm) 0; 
      text-align: center; 
      min-height: 1.5em;
      font-weight: 500;
      padding: var(--spacing-xs);
      border-radius: var(--border-radius);
      transition: all 0.3s ease;
    }
    
    #status { 
      color: var(--success-color); 
    }
    
    #login-status { 
      color: var(--danger-color); 
    }
    
    /* --- 日曆样式复盖 --- */
    #calendar { 
      margin-top: var(--spacing-lg); 
      margin-bottom: var(--spacing-lg);
      min-height: 800px;
    }
    
    .fc { 
      font-size: var(--fc-font-size); 
      max-width: 100%;
      overflow-x: auto;
    }
    
    .fc-toolbar-title { 
      font-size: 1.2em !important; 
      padding: var(--spacing-xs) 0;
    }
    
    .fc .fc-button { 
      padding: .4em .65em; 
      font-size: var(--fc-button-font-size);
      height: auto;
    }
    
    .fc-event-main { 
      cursor: pointer; 
      color: white !important; 
      padding: var(--spacing-xs);
    }
    
    .fc-daygrid-event { 
      padding: 2px;
      margin-bottom: 1px;
    }
    
    .fc-list-event-title b { 
      color: #333; 
    }
    
    .list-event-details { 
      white-space: pre-wrap; 
      margin-top: 5px; 
      color: #333;
      font-size: var(--font-size-sm);
      padding: var(--spacing-xs);
    }
    
    .fc-daygrid-event .fc-event-time { 
      font-weight: bold; 
    }
    
    /* 修復手机版日曆捲动问题 */
    .fc-scroller { 
      -webkit-overflow-scrolling: touch;
    }
    
    .fc-day-grid-container, .fc-scroller, .fc-list-table {
      overflow: visible !important;
    }
    
    /* --- 弹窗样式 --- */
    .modal {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }
    
    .modal-content {
      background: white;
      border-radius: var(--border-radius);
      width: 90%;
      max-width: 600px;
      max-height: 80vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 10px 40px rgba(0,0,0,0.2);
    }
    
    .modal-header {
      padding: var(--spacing-md);
      border-bottom: 1px solid #e0e0e0;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .modal-header h2 {
      margin: 0;
      font-size: var(--font-size-lg);
    }
    
    .close-button {
      background: none;
      border: none;
      font-size: 24px;
      cursor: pointer;
      color: #666;
      width: auto;
      padding: 5px 10px;
      margin: 0;
    }
    
    .close-button:hover {
      color: #333;
    }
    
    .modal-body {
      padding: var(--spacing-md);
      overflow-y: auto;
      flex: 1;
    }
    
    .backup-item {
      padding: var(--spacing-md);
      border: 1px solid #e0e0e0;
      border-radius: var(--border-radius);
      margin-bottom: var(--spacing-sm);
      cursor: pointer;
      transition: all 0.2s ease;
    }
    
    .backup-item:hover {
      background-color: #f5f5f5;
      border-color: var(--primary-color);
    }
    
    .backup-date {
      font-weight: bold;
      color: #333;
      margin-bottom: 5px;
    }
    
    .backup-preview {
      font-size: var(--font-size-sm);
      color: #666;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-family: 'Monaco', 'Menlo', monospace;
    }
    
    .backup-actions {
      margin-top: var(--spacing-sm);
      display: flex;
      gap: var(--spacing-xs);
    }
    
    .backup-action-btn {
      padding: 5px 10px;
      font-size: 12px;
      border-radius: 4px;
      border: none;
      cursor: pointer;
      transition: background-color 0.2s ease;
    }
    
    .restore-btn {
      background-color: var(--success-color);
      color: white;
    }
    
    .restore-btn:hover {
      background-color: #218838;
    }
    
    /* --- 桌面版复盖样式 --- */
    @media (min-width: 768px) { 
      body { 
        padding: var(--spacing-lg); 
      }
      
      .container { 
        padding: var(--spacing-lg); 
        border-radius: var(--border-radius); 
      }
      
      h1 { 
        font-size: 2em; 
      }
      
      h2 { 
        font-size: 1.5em; 
      }
      
      button { 
        width: auto; 
        padding: 10px 20px;
        margin-right: var(--spacing-sm);
      }
      
      .fc-toolbar-title {
        font-size: 1.5em !important;
      }
      
      .fc .fc-button {
        padding: .4em .8em;
      }
    }
  </style>
  <script src='https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/index.global.min.js'><\/script>
  <script src='https://cdn.jsdelivr.net/npm/@fullcalendar/core/locales/zh-hk.global.js'><\/script>
</head>
<body>
  <div id="login-container" class="container">
    <h1>请输入密码</h1>
    <input type="password" id="passwordInput" placeholder="密码">
    <button id="loginButton">登入</button>
    <p id="login-status"></p>
  </div>

  <div id="app-container" class="container hidden">
    <h1>工作时间表月曆 - Nodeseek</h1>

    <div id="calendar"></div>

    <h2>输入工作安排</h2>
    
    <div class="format-hint">
      <strong>📝 格式说明：</strong>每行一项工作，用 <code>|</code> 分隔各项资料
      <br><br>
      <strong>建议格式化技巧：</strong>
      <ul style="margin: 10px 0; padding-left: 20px;">
        <li>同一个案的工作可以用<strong>空行</strong>分组</li>
        <li>相似的工作可以放在一起，便于管理</li>
        <li>长描述可以适当换行，系统会自动处理</li>
        <li>使用 <code>-- 註解 --</code> 来标记不同类型的工作</li>
        <li>使用 <code>//</code> 或 <code>#</code> 开头来註解某一行（不会显示在日曆中）</li>
      </ul>
      
      <strong>范例格式：</strong>
      <code class="format-example">2025年10月10日 | 13:30-20:00 | 陈大文 | 地点: 陈大文大厦</code>
    </div>
    
    <div class="tool-buttons">
      <button type="button" class="tool-button" id="formatButton">
        🎨 自动格式化
      </button>
      <button type="button" class="tool-button" id="groupButton">
        📋 依个案分组
      </button>
      <button type="button" class="tool-button" id="backupButton">
        ⏱️ 查看备份
      </button>
      <button type="button" class="tool-button clear" id="clearButton">
        🗑️ 清空内容
      </button>
    </div>
    
    <textarea id="textInput" placeholder="请依照上述格式输入您的行程...

建议：
• 同一个案的工作可以用空行分开
• 重複性工作可以先写一个完整的，再複製修改日期
• 使用 -- 註解 -- 来标记不同类型的工作
• 使用 // 或 # 开头来註解某一行（不会显示在日曆中）

范例：
2025年10月10日 | 13:30-20:00 | 陈大文 | 地点: 陈大文大厦"></textarea>
    
    <button id="saveButton">储存及更新月曆</button>
    <div id="status"></div>
    
    <!-- 备份管理弹窗 -->
    <div id="backupModal" class="modal hidden">
      <div class="modal-content">
        <div class="modal-header">
          <h2>📋 备份历史记录</h2>
          <button class="close-button" id="closeBackupModal">✕</button>
        </div>
        <div class="modal-body">
          <p style="color: #666; font-size: 14px; margin-bottom: 15px;">
            系统自动保留最近 100 次储存记录，点击可预览或还原。
          </p>
          <div id="backupList"></div>
        </div>
      </div>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const basePath = "${basePath}";
      const loginContainer = document.getElementById('login-container');
      const appContainer = document.getElementById('app-container');
      const passwordInput = document.getElementById('passwordInput');
      const loginButton = document.getElementById('loginButton');
      const loginStatus = document.getElementById('login-status');
      
      const calendarEl = document.getElementById('calendar');
      const textInput = document.getElementById('textInput');
      const saveButton = document.getElementById('saveButton');
      const statusEl = document.getElementById('status');
      const backupModal = document.getElementById('backupModal');
      const closeBackupModal = document.getElementById('closeBackupModal');
      let calendar;

      function initializeApp() {
        loginContainer.classList.add('hidden');
        appContainer.classList.remove('hidden');

        calendar = new FullCalendar.Calendar(calendarEl, {
          initialView: 'dayGridMonth',
          locale: 'zh-hk',
          timeZone: 'local',
          headerToolbar: {
            left: 'prev,next',
            center: 'title',
            right: 'today dayGridMonth,listMonth'
          },
          eventClick: function(info) {
            if (!info.view.type.startsWith('list')) {
              info.jsEvent.preventDefault();
              const title = info.event.title;
              const details = info.event.extendedProps.details;
              const startTime = info.event.start.toLocaleTimeString('zh-hk', { hour: '2-digit', minute: '2-digit', hour12: false });
              const endTime = info.event.end ? info.event.end.toLocaleTimeString('zh-hk', { hour: '2-digit', minute: '2-digit', hour12: false }) : '';
              alert(
                '工作项目: ' + title + '\\n' +
                '时间: ' + startTime + ' - ' + endTime + '\\n\\n' +
                '详细描述:\\n' + details
              );
            }
          },
          eventContent: function(arg) {
            if (arg.view.type.startsWith('list')) {
              const details = arg.event.extendedProps.details;
              let container = document.createElement('div');
              let titleEl = document.createElement('b');
              titleEl.textContent = arg.event.title;
              container.appendChild(titleEl);
              let detailsEl = document.createElement('div');
              detailsEl.className = 'list-event-details';
              detailsEl.textContent = details;
              container.appendChild(detailsEl);
              return { domNodes: [container] };
            }
            return {
              html: \`<div class="fc-event-time">\${arg.timeText}</div><div class="fc-event-title">\${arg.event.title}</div>\`
            };
          }
        });

        // 添加工具按钮事件监听器
        const formatButton = document.getElementById('formatButton');
        const groupButton = document.getElementById('groupButton');
        const clearButton = document.getElementById('clearButton');
        const backupButton = document.getElementById('backupButton');

        if (formatButton) {
          formatButton.addEventListener('click', formatTextContent);
        }

        if (groupButton) {
          groupButton.addEventListener('click', groupByCase);
        }

        if (clearButton) {
          clearButton.addEventListener('click', () => {
            if (confirm('确定要清空所有内容吗？')) {
              textInput.value = '';
              statusEl.textContent = '内容已清空';
            }
          });
        }
        
        if (backupButton) {
          backupButton.addEventListener('click', showBackupModal);
        }
        
        if (closeBackupModal) {
          closeBackupModal.addEventListener('click', () => {
            backupModal.classList.add('hidden');
          });
        }
        
        // 点击弹窗外部关闭
        backupModal.addEventListener('click', (e) => {
          if (e.target === backupModal) {
            backupModal.classList.add('hidden');
          }
        });

        calendar.render();
        loadSchedule();
      }

      // 格式化文本内容
      function formatTextContent() {
        const content = textInput.value;
        if (!content.trim()) return;
        
        const lines = content.split('\\n');
        let formattedLines = [];
        let lastWasEmpty = false;
        
        lines.forEach((line, index) => {
          const trimmedLine = line.trim();
          
          // 跳过註解行（以 -- 开始和结束）
          if (trimmedLine.startsWith('--') && trimmedLine.endsWith('--')) {
            if (!lastWasEmpty && formattedLines.length > 0) {
              formattedLines.push(''); // 註解前加空行
            }
            formattedLines.push(trimmedLine);
            formattedLines.push(''); // 註解后加空行
            lastWasEmpty = true;
            return;
          }
          
          // 处理数据行
          if (trimmedLine && trimmedLine.includes('|')) {
            const parts = trimmedLine.split('|').map(part => part.trim());
            if (parts.length >= 3) {
              formattedLines.push(parts.join(' | '));
              lastWasEmpty = false;
            }
          } else if (trimmedLine === '') {
            if (!lastWasEmpty) {
              formattedLines.push('');
              lastWasEmpty = true;
            }
          } else {
            formattedLines.push(trimmedLine);
            lastWasEmpty = false;
          }
        });
        
        textInput.value = formattedLines.join('\\n');
        statusEl.textContent = '格式化完成！';
      }

      // 依个案分组
      // 在前端 JavaScript 的 groupByCase 函数中修改排序逻辑

      // 依个案分组
      function groupByCase() {
        const content = textInput.value;
        if (!content.trim()) return;
        
        const lines = content.split('\\n');
        const groups = {};
        const others = [];
        let currentGroup = null;
        
        lines.forEach(line => {
          const trimmedLine = line.trim();
          
          // 跳过空行
          if (trimmedLine === '') {
            return;
          }
          
          // 检查是否为现有的分组标题
          const groupTitleMatch = trimmedLine.match(/^--\\s*(.+?)\\s*--$/);
          if (groupTitleMatch) {
            currentGroup = groupTitleMatch[1]; // 提取分组名称
            return;
          }
          
          // 处理数据行
          if (trimmedLine.includes('|')) {
            const parts = trimmedLine.split('|').map(part => part.trim());
            if (parts.length >= 3) {
              const caseName = parts[2]; // 个案名称
              
              // 如果当前在某个分组中，使用分组名称，否则使用个案名称
              const groupKey = currentGroup || caseName;
              
              if (!groups[groupKey]) {
                groups[groupKey] = [];
              }
              groups[groupKey].push(trimmedLine);
            }
          } else {
            // 非数据行，放入其他内容
            others.push(trimmedLine);
            currentGroup = null; // 重置当前分组
          }
        });
        
        let result = [];
        
        // 先放其他内容（非分组的内容）
        if (others.length > 0) {
          others.forEach(other => {
            result.push(other);
          });
          if (others.length > 0) {
            result.push(''); // 其他内容后加空行
          }
        }
        
        // 计算每个分组中最早的日期
        const groupEarliestDates = {};
        Object.keys(groups).forEach(groupName => {
          const dates = groups[groupName].map(line => extractDateFromLine(line));
          // 找出最早的日期
          groupEarliestDates[groupName] = new Date(Math.min(...dates));
        });
        
        // 按分组中最早的日期排序
        const sortedGroupNames = Object.keys(groups).sort((a, b) => {
          const dateA = groupEarliestDates[a];
          const dateB = groupEarliestDates[b];
          
          // 先按日期排序
          const dateDiff = dateA - dateB;
          if (dateDiff !== 0) {
            return dateDiff;
          }
          
          // 如果日期相同，按名称排序
          return a.localeCompare(b, 'zh-HK');
        });
        
        sortedGroupNames.forEach((groupName, index) => {
          // 只有在有多个项目时才添加分组标题
          if (groups[groupName].length > 1 || sortedGroupNames.length > 1) {
            result.push(\`-- \${groupName} --\`);
          }
          
          // 按日期排序同一个案的项目
          const sortedEvents = groups[groupName].sort((a, b) => {
            const dateA = extractDateFromLine(a);
            const dateB = extractDateFromLine(b);
            return dateA - dateB;
          });
          
          result.push(...sortedEvents);
          
          // 最后一组不加空行
          if (index < sortedGroupNames.length - 1) {
            result.push('');
          }
        });
        
        textInput.value = result.join('\\n');
        statusEl.textContent = '已依个案分组并按日期排序！';
      }
      
      // 辅助函数：从行中提取日期
      function extractDateFromLine(line) {
        const parts = line.split('|');
        if (parts.length > 0) {
          const dateStr = parts[0].trim();
          
          // 尝试解析完整年份格式
          let dateMatch = dateStr.match(/(\\d{4})年(\\d+)月(\\d+)日/);
          if (dateMatch) {
            return new Date(
              parseInt(dateMatch[1], 10),
              parseInt(dateMatch[2], 10) - 1,
              parseInt(dateMatch[3], 10)
            );
          }
          
          // 尝试解析简化格式
          dateMatch = dateStr.match(/(\\d+)月(\\d+)日/);
          if (dateMatch) {
            const currentYear = new Date().getFullYear();
            return new Date(
              currentYear,
              parseInt(dateMatch[1], 10) - 1,
              parseInt(dateMatch[2], 10)
            );
          }
        }
        
        // 如果无法解析日期，返回一个很早的日期
        return new Date(1900, 0, 1);
      }

      // 显示备份列表
      async function showBackupModal() {
        try {
          const response = await fetch(\`\${basePath}/api/backups\`);
          if (!response.ok) throw new Error('无法载入备份列表');
          
          const backups = await response.json();
          const backupList = document.getElementById('backupList');
          
          if (backups.length === 0) {
            backupList.innerHTML = '<p style="text-align: center; color: #999;">尚无备份记录</p>';
          } else {
            backupList.innerHTML = backups.map(backup => \`
              <div class="backup-item">
                <div class="backup-date">📅 \${backup.date}</div>
                <div class="backup-preview">\${backup.preview}</div>
                <div class="backup-actions">
                  <button class="backup-action-btn restore-btn" onclick="restoreBackup('\${backup.id}')">
                    还原此版本
                  </button>
                </div>
              </div>
            \`).join('');
          }
          
          backupModal.classList.remove('hidden');
        } catch (error) {
          console.error('载入备份失败:', error);
          alert('载入备份列表失败');
        }
      }
      
      // 还原备份
      window.restoreBackup = async function(backupId) {
        if (!confirm('确定要还原此备份吗？当前内容将被复盖。')) {
          return;
        }
        
        try {
          const response = await fetch(\`\${basePath}/api/restore\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backupId })
          });
          
          if (!response.ok) throw new Error('还原失败');
          
          const result = await response.json();
          
          // 更新界面
          textInput.value = result.data.rawText || '';
          calendar.removeAllEvents();
          if (result.data.events && result.data.events.length > 0) {
            calendar.addEventSource(result.data.events);
          }
          
          // 关闭弹窗
          backupModal.classList.add('hidden');
          statusEl.textContent = '✅ 备份已成功还原！';
          
          setTimeout(() => {
            statusEl.textContent = '';
          }, 3000);
        } catch (error) {
          console.error('还原失败:', error);
          alert('还原备份失败');
        }
      };

      async function loadSchedule() {
        statusEl.textContent = '正在载入行程...';
        try {
          const response = await fetch(\`\${basePath}/api/schedule\`, { cache: 'no-store' });
          if (response.status === 401) {
             showLogin();
             return;
          }
          if (!response.ok) throw new Error('无法载入行程');
          
          const data = await response.json();
          
          if (data.rawText !== undefined) textInput.value = data.rawText;
          else textInput.value = '';

          calendar.removeAllEvents();
          if (data.events && data.events.length > 0) calendar.addEventSource(data.events);
          
          statusEl.textContent = '行程已载入。';
        } catch (error) {
          console.error('载入失败:', error);
          statusEl.textContent = '无法载入行程。';
        }
      }

      saveButton.addEventListener('click', async () => {
        const content = textInput.value;
        statusEl.textContent = '正在储存...';
        try {
          const response = await fetch(\`\${basePath}/api/schedule\`, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: content
          });
          if (!response.ok) throw new Error('储存失败');
          statusEl.textContent = '储存成功！正在从云端同步...';
          await loadSchedule();
        } catch (error) {
           console.error('储存失败:', error);
           statusEl.textContent = '储存失败，请稍后再试。';
        }
      });
      
      const handleLoginAttempt = async () => {
        const password = passwordInput.value;
        if (!password) return;
        loginStatus.textContent = '正在验证...';
        try {
          const response = await fetch(\`\${basePath}/api/login\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
          });
          
          const data = await response.json();
          
          if (response.ok) {
            initializeApp();
          } else {
            loginStatus.textContent = data.error || '密码错误！';
            passwordInput.value = '';
          }
        } catch (error) {
          loginStatus.textContent = '登入时发生错误。';
        }
      };

      loginButton.addEventListener('click', handleLoginAttempt);
      passwordInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          handleLoginAttempt();
        }
      });

      function showLogin() {
        appContainer.classList.add('hidden');
        loginContainer.classList.remove('hidden');
      }

      async function checkInitialAuth() {
        try {
          const response = await fetch(\`\${basePath}/api/schedule\`);
          if (response.ok) {
            initializeApp();
          } else {
            showLogin();
          }
        } catch (error) {
          console.error("Auth check failed:", error);
          showLogin();
        }
      }

      checkInitialAuth();
    });
  <\/script>
</body>
</html>
`;
}
