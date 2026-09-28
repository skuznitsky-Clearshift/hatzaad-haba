# שרת הסנכרון — next-step-sync

כל שינוי שמועלה לתיקייה הזאת נפרס אוטומטית ל-Cloudflare.
ההגדרות יושבות ב-wrangler.jsonc, גם כאן וגם בשורש הריפו —
העותק בשורש קיים כדי שלא יידרש למלא "Root directory" בדשבורד.

הסודות (SECRET, ADMIN_SECRET) אינם בקוד. הם מוגדרים ב-Cloudflare
ופריסה לא נוגעת בהם.

שחזור אם משהו נשבר: Cloudflare ← next-step-sync ← Deployments
← Rollback. לחיצה אחת.

חובר ל-GitHub ב-28.9.2026.
