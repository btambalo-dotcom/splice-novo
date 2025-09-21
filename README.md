# Splice Admin App — Final (Completo)

Recursos principais:
- Login/senha e papéis (admin/usuário)
- Apenas o primeiro cadastro vira admin; depois só admin cria usuários
- Admin: criar usuários, alternar admin, reset de senha
- Registros: dispositivo, nº de fusões, até 6 fotos (png/jpg/jpeg/gif/webp)
- Relatórios com filtros por datas/usuário, totais por dispositivo, totais por usuário
- Gráficos (Chart.js) + export CSV/XLSX (com abas)
- Download de fotos em ZIP por dispositivos filtrados
- Rota de reset de admin com token (desativada por padrão)

## Rodar local
```bash
pip install -r requirements.txt
python app.py
# http://localhost:5000
```
- Primeiro acesso: /register para criar o admin (se não houver usuários)
- Depois: /login

## Deploy Render
- Start: `gunicorn app:app`
- Build: `pip install -r requirements.txt`
- Env Vars obrigatórias:
    - `SECRET_KEY`
    - `MAX_CONTENT_LENGTH_MB=20`
- (opcionais de emergência):
    - `FORCE_RESET_ADMIN=1`
    - `RESET_ADMIN_TOKEN=seu_token`
    - `NEW_ADMIN_PASSWORD=nova123`
- Disk: monte `/opt/render/project/src/static/uploads`

## Rotas principais
- `/register`, `/login`, `/logout`
- `/` (dashboard), `/new`, `/record/<id>`, `/uploads/<arquivo>`
- `/admin`, `/admin/users`, `/admin/records`
- `/admin/reports`, `/admin/reports.csv`, `/admin/reports.xlsx`, `/admin/reports_users.csv`
- `/admin/photos`, `/admin/photos.zip` (POST)
- `/force_reset_admin?token=SEU_TOKEN` (se `FORCE_RESET_ADMIN=1`)
