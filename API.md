# API

FOR guests:

[v]    / GET                       - Домашняя welcome страничка сайта,
[ ]	   /about                      - О сайте
[v]    /403 GET                    - 403 page,
[ ]    /auth/login GET             - login для пользователя сайта,
[ ]    /auth/login POST            - Обработка login для пользователя сайта,

[ ]   /regions/:country_id GET     - Запрос регионов только для :country_id = USA

FOR users: /room

[ ] /room/ GET                     - Seotask form
[ ] /room/seotask POST             - Send seotask form
[ ] /room/seotasks GET