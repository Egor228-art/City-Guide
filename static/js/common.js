// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', function() {
    checkAuthButtonsState();
    initSecretKeys();
    initFavorites();
    initFooterButtons();
    initAuthForms();
});

// Секретная комбинация клавиш (Konami Code)
window.konamiCode = [];
window.secretCode = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight'];
window.authButtonsVisible = false;

function initSecretKeys() {
    console.log('🔐 Initializing secret keys...');

    document.addEventListener('keydown', (e) => {
        window.konamiCode.push(e.code);
        console.log('Key pressed:', e.code, 'Sequence:', window.konamiCode);

        if (window.konamiCode.length > window.secretCode.length) {
            window.konamiCode.shift();
        }

        if (JSON.stringify(window.konamiCode) === JSON.stringify(window.secretCode)) {
            console.log('🎉 Secret code activated!');
            showAuthButtons(true);
            window.konamiCode = [];
        }
    });
}

// Синхронизация между вкладками
window.addEventListener('storage', function(event) {
    if (event.key === 'authButtonsVisible') {
        checkAuthButtonsState();
    }
    if (event.key === 'username') {
        updateUserInfo();
    }
    if (event.key === 'favorites') {
        updateFavoritesCount();
        markExistingFavorites();
    }
});

// Функция для работы кнопок авторизации
function checkAuthButtonsState() {
    const savedState = localStorage.getItem('authButtonsVisible');
    const isLoggedIn = localStorage.getItem('username');

    // Если пользователь уже авторизован, показываем кнопки
    if (isLoggedIn) {
        window.authButtonsVisible = true;
        showAuthButtons(false);
    } else if (savedState === 'true') {
        window.authButtonsVisible = true;
        showAuthButtons(false);
    } else {
        // Скрываем кнопки при загрузке
        const authButtons = document.querySelector('.auth-buttons');
        if (authButtons) {
            authButtons.style.display = 'none';
        }
    }
}

function showAuthButtons(withAnimation = true) {
    const authButtons = document.querySelector('.auth-buttons');
    const adminButton = document.getElementById('adminButton');

    if (!authButtons) {
        console.error('❌ Auth buttons element not found!');
        return;
    }

    console.log('👤 Showing auth buttons');

    // Сохраняем состояние
    window.authButtonsVisible = true;
    localStorage.setItem('authButtonsVisible', 'true');

    // Показываем кнопки
    authButtons.style.display = 'flex';

    if (withAnimation) {
        authButtons.style.animation = 'secretReveal 0.8s ease-in-out';
    }

    // Также показываем админку если пользователь авторизован
    if (adminButton) {
        adminButton.style.display = 'flex';
    }
}

function hideAuthButtons() {
    const authButtons = document.querySelector('.auth-buttons');
    if (!authButtons) {
        console.error('❌ Auth buttons element not found!');
        return;
    }

    console.log('👤 Hiding auth buttons');

    // Обновляем состояние
    window.authButtonsVisible = false;
    localStorage.setItem('authButtonsVisible', 'false');

    authButtons.style.animation = 'secretHide 0.5s ease-in-out';
    setTimeout(() => {
        authButtons.style.display = 'none';
    }, 500);
}

// Инициализация кнопок футера
function initFooterButtons() {

    const homeLink = document.getElementById('homeLink');
    const aboutLink = document.getElementById('aboutLink');
    const contactsLink = document.getElementById('contactsLink');
    const luckyButton = document.getElementById('luckyButton');

    if (homeLink) {
        homeLink.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = "/";
        });
    }

    if (aboutLink) {
        aboutLink.addEventListener('click', function(e) {
            e.preventDefault();
            const aboutModal = document.getElementById('aboutModal');
            if (aboutModal) aboutModal.style.display = 'flex';
        });
    }

    if (contactsLink) {
        contactsLink.addEventListener('click', function(e) {
            e.preventDefault();
            // Ваш существующий код для стрелки к контактам
        });
    }

    if (luckyButton) {
        luckyButton.addEventListener('click', function(e) {
            e.preventDefault();
            luckyButton.innerHTML = '🌀 Ищем...';
            luckyButton.style.pointerEvents = 'none';

            fetch('/api/random-place')
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.place_url) {
                        window.location.href = data.place_url;
                    } else {
                        alert('Не удалось найти случайное заведение');
                        luckyButton.innerHTML = 'Случайное заведение';
                        luckyButton.style.pointerEvents = 'auto';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Произошла ошибка при поиске случайного заведения');
                    luckyButton.innerHTML = 'Случайное заведение';
                    luckyButton.style.pointerEvents = 'auto';
                });
        });
    }
}

//Кнопки Футера - Начало

const homeLink = document.getElementById('homeLink');
const aboutLink = document.getElementById('aboutLink');
const contactsLink = document.getElementById('contactsLink');
const helpLink = document.getElementById('helpLink');
const aboutModal = document.getElementById('aboutModal');
const closeModal = document.getElementById('closeModal');
const arrowContainer = document.getElementById('arrowContainer');
const arrowLine = document.getElementById('arrowLine');
const arrowHead = document.getElementById('arrowHead');
const contactsTitle = document.getElementById('contactsTitle');

// Обработчик для кнопки "Главная"
homeLink.addEventListener('click', function(e) {
    e.preventDefault();
    // В реальном приложении здесь будет переход на главную страницу
    window.location.href = "/";
});

// Обработчик для кнопки "О проекте"
aboutLink.addEventListener('click', function(e) {
    e.preventDefault();
    aboutModal.style.display = 'flex';
});

// Обработчик для закрытия модального окна
closeModal.addEventListener('click', function() {
    aboutModal.style.display = 'none';
});

// Закрытие модального окна при клике вне его
window.addEventListener('click', function(e) {
    if (e.target === aboutModal) {
        aboutModal.style.display = 'none';
    }
});

// Обработчик для кнопки "Контакты"
contactsLink.addEventListener('click', function(e) {
    e.preventDefault();

    // Получаем позиции элементов относительно документа
    const contactsLinkRect = contactsLink.getBoundingClientRect();
    const contactsTitle = document.querySelector('.footer-section.contact h3');
    const contactsTitleRect = contactsTitle.getBoundingClientRect();

    // Добавляем scroll offset к координатам
    const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
    const scrollY = window.pageYOffset || document.documentElement.scrollTop;

    const startX = contactsLinkRect.left + scrollX + contactsLinkRect.width + 10;
    const startY = contactsLinkRect.top + scrollY + contactsLinkRect.height / 2;

    const endX = contactsTitleRect.left + scrollX - 5;
    const endY = contactsTitleRect.top + scrollY + contactsTitleRect.height;

    // Удаляем предыдущую стрелку если есть
    const existingArrow = document.querySelector('.arrow-to-contacts');
    if (existingArrow) {
        existingArrow.remove();
    }

    // Создаем контейнер для SVG стрелки
    const arrowContainer = document.createElement('div');
    arrowContainer.className = 'arrow-to-contacts';
    document.body.appendChild(arrowContainer);

    // Создаем SVG для стрелки с завитушкой
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "100%");
    svg.style.position = 'absolute';
    svg.style.top = '0';
    svg.style.left = '0';
    svg.style.pointerEvents = 'none';

    // Вычисляем границы для SVG
    const minX = Math.min(startX, endX) - 50;
    const minY = Math.min(startY, endY) - 50;
    const maxX = Math.max(startX, endX) + 50;
    const maxY = Math.max(startY, endY) + 50;
    const width = maxX - minX;
    const height = maxY - minY;

    // Создаем путь с завитушкой
    const path = document.createElementNS(svgNS, "path");
    const curveIntensity = 80;

    // Путь с красивой кривой
    const pathData = `M ${startX - minX} ${startY - minY}
                     C ${startX - minX + curveIntensity} ${startY - minY - curveIntensity},
                       ${endX - minX - curveIntensity} ${endY - minY - curveIntensity},
                       ${endX - minX} ${endY - minY}`;

    path.setAttribute("d", pathData);
    path.setAttribute("class", "arrow-path");
    path.style.filter = 'drop-shadow(0 0 2px rgba(52, 152, 219, 0.5))';

    // Создаем головку стрелки
    const arrowHead = document.createElementNS(svgNS, "polygon");
    arrowHead.setAttribute("points", "0,0 -10,-7 -10,7");
    arrowHead.setAttribute("class", "arrow-head");
    arrowHead.setAttribute("fill", "#3498db");

    // Вычисляем угол для головки стрелки
    const pathElement = document.createElementNS(svgNS, "path");
    pathElement.setAttribute("d", pathData);
    const pathLength = pathElement.getTotalLength();
    const point = pathElement.getPointAtLength(Math.max(0, pathLength - 1));
    const pointBefore = pathElement.getPointAtLength(Math.max(0, pathLength - 20));
    const angle = Math.atan2(point.y - pointBefore.y, point.x - pointBefore.x) * 180 / Math.PI;

    arrowHead.setAttribute("transform", `translate(${endX - minX},${endY - minY}) rotate(${angle})`);
    arrowHead.style.filter = 'drop-shadow(0 0 2px rgba(52, 152, 219, 0.5))';

    // Устанавливаем размеры SVG
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    arrowContainer.style.width = width + 'px';
    arrowContainer.style.height = height + 'px';
    arrowContainer.style.left = minX + 'px';
    arrowContainer.style.top = minY + 'px';
    arrowContainer.style.position = 'absolute'; // Меняем fixed на absolute

    svg.appendChild(path);
    svg.appendChild(arrowHead);
    arrowContainer.appendChild(svg);

    // Показываем стрелку
    arrowContainer.style.opacity = '1';
    arrowContainer.style.transition = 'opacity 0.5s';

    // Добавляем класс для подчёркивания
    contactsTitle.classList.add('contacts-underline');

    // Анимируем прорисовку пути
    setTimeout(() => {
        path.style.transition = 'stroke-dashoffset 1.2s ease-in-out';
        path.style.strokeDashoffset = '0';
        setTimeout(() => {contactsTitle.classList.add('animate');}, 450)
    }, 100);

    // Анимируем появление головки стрелки и подчёркивание
    setTimeout(() => {
        arrowHead.style.opacity = '1';
        arrowHead.style.transition = 'opacity 0.3s ease-in-out';
    }, 550);

    // Удаляем стрелку через 3 секунды
    setTimeout(() => {
        arrowContainer.style.opacity = '0';
        contactsTitle.classList.remove('animate');

        setTimeout(() => {
            if (arrowContainer.parentNode) {
                arrowContainer.parentNode.removeChild(arrowContainer);
            }
            contactsTitle.classList.remove('contacts-underline');
        }, 500);
    }, 2000);
});

// Добавляем после других обработчиков футера
const luckyButton = document.getElementById('luckyButton');

luckyButton.addEventListener('click', function(e) {
    e.preventDefault();

    // Показываем анимацию загрузки
    luckyButton.innerHTML = '🌀 Ищем...';
    luckyButton.style.pointerEvents = 'none';

    fetch('/api/random-place')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.place_url) {
                // Переходим на случайную страницу
                window.location.href = data.place_url;
            } else {
                alert('Не удалось найти случайное заведение');
                luckyButton.innerHTML = 'Мне повезёт';
                luckyButton.style.pointerEvents = 'auto';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Произошла ошибка при поиске случайного заведения');
            luckyButton.innerHTML = 'Мне повезёт';
            luckyButton.style.pointerEvents = 'auto';
        });
});

//Кнопки Футера - Конец

//Код кнопки избранного
function initFavorites() {
    updateFavoritesCount();
    markExistingFavorites();

    // Обработчик для кнопки избранного в шапке
    const headerFavoritesBtn = document.getElementById('header-favorites-btn');
    if (headerFavoritesBtn) {
        headerFavoritesBtn.addEventListener('click', function(event) {
            event.preventDefault();
            event.stopPropagation();

            // Переключаем активное состояние для анимации
            headerFavoritesBtn.classList.toggle('active');

            // Переход на страницу избранного
            window.location.href = '/favorites';
        });
    }

    // Обработчики для кнопок избранного в карточках
    document.querySelectorAll('.favorite-btn').forEach(btn => {
        btn.addEventListener('click', function(event) {
            event.preventDefault();
            event.stopPropagation();

            const itemId = this.dataset.itemId;
            const itemData = this.dataset.item ? JSON.parse(this.dataset.item) : null;
            toggleFavorite(itemId, itemData, this);
        });
    });
}

function toggleFavorite(itemId, itemData, buttonElement) {
    try {
        const favorites = getFavorites();
        const existingIndex = favorites.findIndex(fav => fav.id === itemId);

        if (existingIndex === -1) {
            // Добавляем в избранное
            favorites.push(itemData);
            if (buttonElement) {
                buttonElement.classList.add('active');
            }
        } else {
            // Удаляем из избранного
            favorites.splice(existingIndex, 1);
            if (buttonElement) {
                buttonElement.classList.remove('active');
            }
        }

        saveFavorites(favorites);
        updateFavoritesCount();
        markExistingFavorites();

    } catch (error) {
        console.error('Error toggling favorite:', error);
    }
}

function getFavorites() {
    try {
        return JSON.parse(localStorage.getItem('favorites')) || [];
    } catch (error) {
        console.error('Error getting favorites:', error);
        return [];
    }
}

function saveFavorites(favorites) {
    try {
        localStorage.setItem('favorites', JSON.stringify(favorites));
        window.dispatchEvent(new Event('storage'));
    } catch (error) {
        console.error('Error saving favorites:', error);
    }
}

function updateFavoritesCount() {
    try {
        const favorites = getFavorites();
        const count = favorites.length;
        const counter = document.getElementById('favorites-count');
        const headerBtn = document.getElementById('header-favorites-btn');

        if (counter) {
            counter.textContent = count;
        }

        if (headerBtn) {
            // Очищаем предыдущие таймеры чтобы избежать конфликтов
            if (headerBtn._hideTimeout) {
                clearTimeout(headerBtn._hideTimeout);
            }

            if (count > 0) {
                // Показываем кнопку сразу
                headerBtn.style.display = 'inline-block';
                headerBtn.classList.add('visible');
                setTimeout(() => {
                    headerBtn.style.opacity = '1';
                    headerBtn.style.transform = 'translateY(0)';
                }, 10);
            } else {
                // Скрываем кнопку с задержкой (2 секунды)
                headerBtn.style.opacity = '0';
                headerBtn.style.transform = 'translateY(-10px)';

                headerBtn._hideTimeout = setTimeout(() => {
                    headerBtn.style.display = 'none';
                    headerBtn.classList.remove('visible');
                }, 2000); // 2000ms = 2 секунды задержки
            }
        }
    } catch (error) {
        console.error('Error updating favorites count:', error);
    }
}

function markExistingFavorites() {
    try {
        const favorites = getFavorites();

        // Для кнопок в карточках
        document.querySelectorAll('.favorite-btn').forEach(btn => {
            try {
                const itemId = btn.dataset.itemId;
                if (itemId) {
                    const isFavorite = favorites.some(fav => fav.id === itemId);
                    if (isFavorite) {
                        btn.classList.add('active');
                    } else {
                        btn.classList.remove('active');
                    }
                }
            } catch (error) {
                console.error('Error marking favorite button:', error);
            }
        });
    } catch (error) {
        console.error('Error in markExistingFavorites:', error);
    }
}

// Синхронизация между вкладках
window.addEventListener('storage', function(event) {
    if (event.key === 'favorites') {
        updateFavoritesCount();
        markExistingFavorites();
    }
});

//Конец кода кнопки избранного

function showWindow() {
    document.getElementById('overlay').style.display = 'block';
    const windowElement = document.getElementById('content_window');
    windowElement.classList.add('show');
    windowElement.style.display = 'block';
}

function hideWindow() {
    document.getElementById('overlay').style.display = 'none';
    const windowElement = document.getElementById('content_window');
    windowElement.classList.remove('show');
    windowElement.style.display = 'none';
    document.body.classList.remove('no-scroll');
}

function showWindow1() {
    document.getElementById('overlay').style.display = 'block';
    const windowElement = document.getElementById('content_window2');
    windowElement.classList.add('show');
    windowElement.style.display = 'block';
}

function hideWindow1() {
    document.getElementById('overlay').style.display = 'none';
    const windowElement = document.getElementById('content_window2');
    windowElement.classList.remove('show');
    windowElement.style.display = 'none';
    document.body.classList.remove('no-scroll');
}

// Закрытие окна при клике вне его
document.getElementById('overlay').addEventListener('click', function() {
    const window1 = document.getElementById('content_window');
    const window2 = document.getElementById('content_window2');
    if (window1.classList.contains('show')) {
        hideWindow();
    } else if (window2.classList.contains('show')) {
        hideWindow1();
    }
});

// Обработчики кнопок входа/регистрации
document.getElementById('loginButton').addEventListener('click', showWindow);
document.getElementById('registerButton').addEventListener('click', showWindow1);

// Обработчик для формы регистрации
document.getElementById('regForm').onsubmit = function(event) {
    event.preventDefault();

    const username = document.getElementById('username1').value;
    const password = document.getElementById('password1').value;
    const confirmPassword = document.getElementById('password2').value;
    const secretKey = document.getElementById('secret_key').value;

    if (password !== confirmPassword) {
        alert('Пароли не совпадают');
        return;
    }

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
            document.getElementById('userInfo').style.display = 'flex';
            document.getElementById('overlay').style.display = 'none';
            document.getElementById('content_window2').classList.remove('show');
            document.getElementById('content_window2').style.display = 'none';
            document.getElementById('loginButton').style.display = 'none';
            document.getElementById('registerButton').style.display = 'none';
            localStorage.setItem('username', data.username);
        } else {
            alert(data.message);
        }
    });
};

// Обработчик для формы входа
document.getElementById('loginForm').onsubmit = function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

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
            document.getElementById('userInfo').style.display = 'flex';
            document.getElementById('overlay').style.display = 'none';
            document.getElementById('content_window').classList.remove('show');
            document.getElementById('content_window').style.display = 'none';
            document.getElementById('loginButton').style.display = 'none';
            document.getElementById('registerButton').style.display = 'none';
            localStorage.setItem('username', data.username);
        } else {
            alert(data.message);
        }
    });
};

// Обработчик кнопки выхода
document.querySelector('.btn-logout').addEventListener('click', function() {
    fetch('/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('userInfo').style.display = 'none';
            document.getElementById('loginButton').style.display = 'block';
            document.getElementById('registerButton').style.display = 'block';
            localStorage.removeItem('username');
        } else {
            alert(data.message);
        }
    });
});

// Обновляем обработчик выхода
function initAuthForms() {
    // Обработчик кнопки выхода
    const logoutBtn = document.querySelector('.btn-logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();

            fetch('/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Скрываем информацию пользователя
                    document.getElementById('userInfo').style.display = 'none';
                    document.getElementById('loginButton').style.display = 'block';
                    document.getElementById('registerButton').style.display = 'block';

                    // Убираем админку
                    const adminButton = document.getElementById('adminButton');
                    if (adminButton) {
                        adminButton.style.display = 'none';
                    }

                    // Очищаем localStorage
                    localStorage.removeItem('username');
                    localStorage.removeItem('is_admin');

                    // НЕ скрываем кнопки авторизации, если они были показаны через Konami Code
                    if (!window.authButtonsVisible) {
                        const authButtons = document.querySelector('.auth-buttons');
                        if (authButtons) {
                            authButtons.style.display = 'none';
                        }
                    }

                    console.log('✅ User logged out, auth buttons state:', window.authButtonsVisible);
                } else {
                    alert(data.message);
                }
            })
            .catch(error => {
                console.error('Logout error:', error);
                alert('Ошибка при выходе из системы');
            });
        });
    }
}

// Проверка состояния пользователя при загрузке страницы
window.addEventListener('load', function() {
    const username = localStorage.getItem('username');
    if (username) {
        document.getElementById('welcomeUser').innerText = username;
        document.getElementById('userInfo').style.display = 'flex';
        document.getElementById('loginButton').style.display = 'none';
        document.getElementById('registerButton').style.display = 'none';
    }
});

// Синхронизация состояния пользователя между вкладками
window.addEventListener('storage', function(event) {
    if (event.key === 'username') {
        if (event.newValue) {
            document.getElementById('welcomeUser').innerText = event.newValue;
            document.getElementById('userInfo').style.display = 'flex';
            document.getElementById('loginButton').style.display = 'none';
            document.getElementById('registerButton').style.display = 'none';
        } else {
            document.getElementById('userInfo').style.display = 'none';
            document.getElementById('loginButton').style.display = 'block';
            document.getElementById('registerButton').style.display = 'block';
        }
    }
});