// Имя базы данных
var dbName = 'mongo';

// Имя пользователя
var username = 'admin';

// Пароль пользователя
var password = 'password';

// Создание пользователя
db.createUser({
    user: username,
    pwd: password,
    roles: [{ role: 'readWrite', db: dbName }]
});

// Добавление записи в коллекцию name
db.users.insertOne({ guid: '33b1ff59-184a-46a4-aa38-777f619f5582' });