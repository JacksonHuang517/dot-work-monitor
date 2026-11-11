export function canonicalOrigin(value: string, allowLoopback = false): string {
 const url = new URL(value);
 if (url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Invalid service origin');
 if (url.protocol !== 'https:' && !(allowLoopback && url.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(url.hostname))) throw new Error('HTTPS service origin required');
 return url.origin;
}
