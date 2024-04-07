 #Командлы для Docker:
 ##docker compose up -d build 
 ##Через код в базе создастся пользователь с GUID 33b1ff59-184a-46a4-aa38-777f619f5582
    Запросы:
    для 1 эндпоинта: localhost:8080/get-token?GUID="33b1ff59-184a-46a4-aa38-777f619f5582"
    для 2 эндпоинта: localhost:8080/refresh?refreshToken="рефреш из 1 эндпоинта"&accessToken="аксес из 1 эндпоинта"

###Для начала я решил сделать эндпойнт для выдачи пары Access, Refresh токенов.
###Была создана проверка на существование пользователя по его guid'у.
    ####временно в коде завел двух пользователей, по ним выполняется проверка (в итоговом варианте этого нет, используется БД)
###Для генерации токенов использую популярную библиотеку github.com/golang-jwt/jwt/v5
    ####и access, и refresh токены решил генерировать через библиотеку.
    ####в оба токена вложил ключ, чтобы после выполнить условие "Access, Refresh токены обоюдно связаны..."
###В итоге добился того, что по guid-запросу выдается access и refresh токены.


###Далее развернул базу Mongo, создал пользователей, настроил подключение к базе, добился обновления рефреш токена для юзеров.
###Далее занялся шифрованием рефреш токена при записи в БД.
    ####bcrypt не позволил мне шифровать строку более чем в 72 символа
    ####можно было бы отказаться от генерации рефреша через библиотеку и сделать токен короче, но тогда потеряю проверку по ключу
    ####поэтому решено было использовать sha512 хеширование, так как его рекомендуют в интернете и оно упоминается в задаче

###Затем был сделан 2 эндпоинт через RefreshHandler
    ####Он принимает в запросе refreshToken и accessToken
        #####сначала refreshToken из запроса хешируется по sha512 и ищется в базе
        #####если есть такой рефреш выполняется проверка по ключам между access и refresh токенами
            #####сначала достается ключ из refresh, потом из access и они сравниваются
    ####Если проверка пройдена, то генерируется новый access и refresh токены
    ####Новый refresh токен заменяет старый, что делает невозможность использования старого refresh токена
    
