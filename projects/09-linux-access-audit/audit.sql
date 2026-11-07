-- Scope: only the three declared regular files in the isolated lab.
-- Join observed Linux modes to policy; a bitwise mask detects forbidden access.
SELECT a.path, a.mode, p.forbidden_mask, p.target_mode, p.risk
FROM assets AS a
JOIN policies AS p ON p.path = a.path
WHERE (a.mode & p.forbidden_mask) != 0
ORDER BY a.path;
