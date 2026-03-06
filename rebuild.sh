#!/bin/bash
# Nuclear clean rebuild — wipes all cached images, volumes, containers
set -e

echo "💣  Stopping and removing ALL containers, images, volumes for this project..."
docker compose down --volumes --rmi all 2>/dev/null || true

echo "🧹  Pruning dangling build cache..."
docker builder prune -f 2>/dev/null || true

echo "🔨  Building fresh images (no cache)..."
docker compose build --no-cache

echo "🚀  Starting lab..."
docker compose up

echo ""
echo "✅  Lab is up:"
echo "   Client App   → http://localhost:3002"
echo "   Docs Portal  → http://localhost:3002/docs"
echo "   Auth Server  → http://localhost:3001"
echo "   Resource API → http://localhost:3003"
echo "   Attacker C2  → http://localhost:3004"
echo "   Monitoring   → http://localhost:3005"
echo ""
echo "🔍  Verifying docs portal has new content..."
sleep 3
curl -s http://localhost:3002/docs | grep -o "JetBrains\|nav-atks\|ntab" | head -3 && echo "✅ New portal confirmed" || echo "⚠️  Still serving old content — check logs: docker compose logs client-app"
