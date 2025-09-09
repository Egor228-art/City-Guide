function showWindow() {
    document.getElementById('overlay').style.display = 'block';
    const windowElement = document.getElementById('content_window');
    windowElement.classList.add('show');
    windowElement.style.display = 'block'; // Убедимся, что окно видимо
    document.body.classList.add('no-scroll'); // Предотвращаем скролл страницы
}

function hideWindow() {
    document.getElementById('overlay').style.display = 'none';
    const windowElement = document.getElementById('content_window');
    windowElement.classList.remove('show');
    windowElement.style.display = 'none'; // Скрываем окно
    document.body.classList.remove('no-scroll'); // Возвращаем скролл страницы
}

function showWindow1() {
    document.getElementById('overlay').style.display = 'block';
    const windowElement = document.getElementById('content_window2');
    windowElement.classList.add('show');
    windowElement.style.display = 'block'; // Убедимся, что окно видимо
    document.body.classList.add('no-scroll'); // Предотвращаем скролл страницы
}

function hideWindow1() {
    document.getElementById('overlay').style.display = 'none';
    const windowElement = document.getElementById('content_window2');
    windowElement.classList.remove('show');
    windowElement.style.display = 'none'; // Скрываем окно
    document.body.classList.remove('no-scroll'); // Возвращаем скролл страницы
}

// Закрытие окна при клике вне его
const element = document.getElementById('overlay');
if (element) {
    element.addEventListener('click', function() {
        const window1 = document.getElementById('content_window');
        const window2 = document.getElementById('content_window2');
        if (window1.classList.contains('show')) {
            hideWindow();
        } else if (window2.classList.contains('show')) {
            hideWindow1();
        }
    });
}

// Закрытие окна при нажатии на кнопки внутри окна
document.querySelectorAll('.btnA, .btnB').forEach(function(button) {
    button.addEventListener('click', function() {
        const window1 = document.getElementById('content_window');
        const window2 = document.getElementById('content_window2');
        if (window1.classList.contains('show')) {
            hideWindow();
        } else if (window2.classList.contains('show')) {
            hideWindow1();
        }
    });
});

// Обработчик для формы регистрации
document.getElementById('regForm').onsubmit = function(event) {
    event.preventDefault(); // Предотвращаем отправку формы

    // Получаем данные из формы
    const username = document.getElementById('username1').value;
    const password = document.getElementById('password1').value;
    const confirmPassword = document.getElementById('password2').value;
    const secretKey = document.getElementById('secret_key').value;

    // Проверка совпадения паролей
    if (password !== confirmPassword) {
        alert('Пароли не совпадают');
        return;
    }

    // Отправляем данные на сервер
    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'username': username,
            'password': password,
            'secret_key': secretKey
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('welcomeUser').innerText = data.username;
            document.getElementById('userInfo').style.display = 'block'; // Показываем информацию о пользователе
            document.getElementById('overlay').style.display = 'none';
            document.getElementById('content_window2').classList.remove('show');
            document.getElementById('content_window2').style.display = 'none'; // Скрываем окно
            document.getElementById('loginButton').style.display = 'none';
            document.getElementById('registerButton').style.display = 'none';
            localStorage.setItem('username', data.username);
        } else {
            alert(data.message); // Показываем сообщение об ошибке
        }
    });
};

// Обработчик для формы входа
document.getElementById('loginForm').onsubmit = function(event) {
    event.preventDefault(); // Предотвращаем отправку формы

    // Получаем данные из формы
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Отправляем данные на сервер
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'username': username,
            'password': password
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('welcomeUser').innerText = data.username;
            document.getElementById('userInfo').style.display = 'block'; // Показываем информацию о пользователе
            document.getElementById('overlay').style.display = 'none';
            document.getElementById('content_window').classList.remove('show');
            document.getElementById('content_window').style.display = 'none'; // Скрываем окно
            document.getElementById('loginButton').style.display = 'none';
            document.getElementById('registerButton').style.display = 'none';
            localStorage.setItem('username', data.username);
        } else {
            alert(data.message); // Показываем сообщение об ошибке
        }
    });
};

function logout() {
    fetch('/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('userInfo').style.display = 'none'; // Скрываем информацию о пользователе
            document.getElementById('loginButton').style.display = 'block';
            document.getElementById('registerButton').style.display = 'block';
            localStorage.removeItem('username');
        } else {
            alert(data.message); // Показываем сообщение об ошибке
        }
    });
}

// Проверка состояния пользователя при загрузке страницы
window.addEventListener('load', function() {
    const username = localStorage.getItem('username');
    if (username) {
        document.getElementById('welcomeUser').innerText = username;
        document.getElementById('userInfo').style.display = 'block';
        document.getElementById('loginButton').style.display = 'none';
        document.getElementById('registerButton').style.display = 'none';
    }
});

// Синхронизация состояния пользователя между вкладках
window.addEventListener('storage', function(event) {
    if (event.key === 'username') {
        if (event.newValue) {
            document.getElementById('welcomeUser').innerText = event.newValue;
            document.getElementById('userInfo').style.display = 'block';
            document.getElementById('loginButton').style.display = 'none';
            document.getElementById('registerButton').style.display = 'none';
        } else {
            document.getElementById('userInfo').style.display = 'none';
            document.getElementById('loginButton').style.display = 'block';
            document.getElementById('registerButton').style.display = 'block';
        }
    }
});
