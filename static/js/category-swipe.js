// ==============================================
// УМНАЯ ПАГИНАЦИЯ - БУРГЕР И СВАЙПЫ (ФИНАЛ v3)
// ==============================================

// Глобальный флаг для отслеживания инициализации
window.swipeInitialized = false;
window.isMobileDevice = false;

document.addEventListener('DOMContentLoaded', function() {
    // Принудительно фиксируем overflow при загрузке
    if (window.innerWidth <= 992) {
        document.body.style.overflowX = 'hidden';
        document.documentElement.style.overflowX = 'hidden';
    }
    // Проверяем, мобильное ли устройство
    checkIfMobile();

    if (window.isMobileDevice) {
        initFilterBurger();
        initSwipeNavigation();
        window.swipeInitialized = true;
    } else {
        removeMobileStyles();
    }

    // При изменении размера окна
    window.addEventListener('resize', function() {
        checkIfMobile();

        if (window.isMobileDevice && !window.swipeInitialized) {
            initFilterBurger();
            initSwipeNavigation();
            window.swipeInitialized = true;
        }

        if (!window.isMobileDevice && window.swipeInitialized) {
            removeSwipeFunctionality();
            removeMobileStyles();
            window.swipeInitialized = false;
        }
    });

    // Блокируем жест "назад" браузера на всём документе
    blockBrowserSwipeGesture();
});

// ===== ГЛАВНОЕ ИСПРАВЛЕНИЕ: БЛОКИРОВКА ЖЕСТА "НАЗАД" БРАУЗЕРА =====
function blockBrowserSwipeGesture() {
    let startX = 0;
    let startY = 0;

    document.addEventListener('touchstart', function(e) {
        startX = e.touches[0].pageX;
        startY = e.touches[0].pageY;
    }, { passive: false });

    document.addEventListener('touchmove', function(e) {
        if (!window.isMobileDevice) return;

        const currentX = e.touches[0].pageX;
        const currentY = e.touches[0].pageY;
        const deltaX = currentX - startX;
        const deltaY = currentY - startY;

        // Если горизонтальное движение больше вертикального - блокируем ВСЁ
        if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 10) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
    }, { passive: false });

    // Дополнительно блокируем на уровне window
    window.addEventListener('touchmove', function(e) {
        if (!window.isMobileDevice) return;

        const currentX = e.touches[0].pageX;
        const currentY = e.touches[0].pageY;
        const deltaX = currentX - startX;
        const deltaY = currentY - startY;

        if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 10) {
            e.preventDefault();
        }
    }, { passive: false });
}

// Проверка, мобильное ли устройство
function checkIfMobile() {
    const width = window.innerWidth;
    const isTouchDevice = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);

    window.isMobileDevice = width <= 992 && isTouchDevice;

    return window.isMobileDevice;
}

// Удаление мобильных стилей на десктопе
function removeMobileStyles() {
    const container = document.querySelector('.restaurants-container');
    if (container) {
        container.style.transition = '';
        container.style.transform = '';
        container.style.touchAction = '';
        container.style.overscrollBehavior = '';
        container.style.willChange = '';
    }

    const navbar = document.querySelector('.navbar');
    if (navbar) {
        navbar.style.transform = '';
        navbar.style.backfaceVisibility = '';
        navbar.style.willChange = '';
    }

    const styles = document.querySelectorAll('style[data-swipe-styles]');
    styles.forEach(style => style.remove());
}

// Удаление функционала свайпов
function removeSwipeFunctionality() {
    const burgerBtn = document.querySelector('.filter-burger-btn');
    if (burgerBtn) burgerBtn.remove();

    const sidebar = document.querySelector('.filter-sidebar');
    if (sidebar) sidebar.remove();

    const overlay = document.querySelector('.filter-overlay');
    if (overlay) overlay.remove();

    const smartPagination = document.querySelector('.smart-pagination');
    if (smartPagination) {
        smartPagination.style.position = '';
        smartPagination.style.bottom = '';
        smartPagination.style.left = '';
        smartPagination.style.transform = '';
        smartPagination.style.width = '';
        smartPagination.style.maxWidth = '';
        smartPagination.style.padding = '';
        smartPagination.style.borderRadius = '';
        smartPagination.style.gap = '';
    }

    const filtersContainer = document.querySelector('.filters-container-left');
    if (filtersContainer) {
        filtersContainer.style.display = '';
    }

    const restaurantsContainer = document.querySelector('.restaurants-container');
    if (restaurantsContainer) {
        restaurantsContainer.style.margin = '';
        restaurantsContainer.style.paddingBottom = '';
        restaurantsContainer.style.transition = '';
        restaurantsContainer.style.transform = '';
        restaurantsContainer.style.willChange = '';
    }
}

// ===== БУРГЕР-МЕНЮ ДЛЯ ФИЛЬТРОВ =====
function initFilterBurger() {
    if (!window.isMobileDevice) return;

    const smartPagination = document.querySelector('.smart-pagination');
    if (!smartPagination) return;

    if (document.querySelector('.filter-burger-btn')) return;

    const burgerBtn = document.createElement('button');
    burgerBtn.className = 'filter-burger-btn';
    burgerBtn.innerHTML = '☰';
    burgerBtn.setAttribute('aria-label', 'Фильтры');

    smartPagination.appendChild(burgerBtn);

    const overlay = document.createElement('div');
    overlay.className = 'filter-overlay';
    document.body.appendChild(overlay);

    const sidebar = document.createElement('div');
    sidebar.className = 'filter-sidebar';

    const filtersContainer = document.querySelector('.filters-container-left');
    if (filtersContainer) {
        sidebar.innerHTML = `
            <div class="filter-sidebar-header">
                <h3>Фильтры</h3>
                <button class="filter-sidebar-close">&times;</button>
            </div>
            <div class="filter-options">
                ${filtersContainer.innerHTML}
            </div>
        `;
        document.body.appendChild(sidebar);

        const originalSelect = filtersContainer.querySelector('#sortFilter');
        const sidebarSelect = sidebar.querySelector('#sortFilter');

        if (originalSelect && sidebarSelect) {
            sidebarSelect.value = originalSelect.value;

            sidebarSelect.addEventListener('change', function() {
                originalSelect.value = this.value;
                if (typeof window.applyFilters === 'function') {
                    window.applyFilters();
                } else if (typeof applyFilters === 'function') {
                    applyFilters();
                }
                closeFilterSidebar();
            });
        }
    }

    function openFilterSidebar() {
        sidebar.classList.add('open');
        overlay.classList.add('open');
        document.body.style.overflow = 'hidden';
    }

    function closeFilterSidebar() {
        sidebar.classList.remove('open');
        overlay.classList.remove('open');
        document.body.style.overflow = '';
    }

    burgerBtn.addEventListener('click', openFilterSidebar);

    const closeBtn = sidebar.querySelector('.filter-sidebar-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeFilterSidebar);
    }

    overlay.addEventListener('click', closeFilterSidebar);

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && sidebar.classList.contains('open')) {
            closeFilterSidebar();
        }
    });
}

// ===== НАВИГАЦИЯ СВАЙПАМИ С АНИМАЦИЕЙ (ТОЛЬКО НА МОБИЛЬНЫХ) =====
function initSwipeNavigation() {
    if (!window.isMobileDevice) return;
    if (window.innerWidth > 992) return;

    const container = document.querySelector('.restaurants-container');
    if (!container) return;

    container.style.transition = 'transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 0.2s ease';
    container.style.willChange = 'transform, opacity';
    container.style.touchAction = 'pan-y';
    container.style.overscrollBehavior = 'none';

    let touchStartX = 0;
    let touchStartY = 0;
    let touchCurrentX = 0;
    let isSwiping = false;
    let isAnimating = false;
    const swipeThreshold = 100;
    const maxDragDistance = 150;

    container.addEventListener('touchstart', function(e) {
        if (!window.isMobileDevice) return;
        if (isAnimating) return;

        touchStartX = e.touches[0].pageX;
        touchStartY = e.touches[0].pageY;
        touchCurrentX = touchStartX;
        isSwiping = true;

        container.style.transition = 'none';
    }, { passive: true });

    container.addEventListener('touchmove', function(e) {
        if (!window.isMobileDevice) return;
        if (!isSwiping || isAnimating) return;

        const currentX = e.touches[0].pageX;
        const currentY = e.touches[0].pageY;
        const deltaX = currentX - touchStartX;
        const deltaY = currentY - touchStartY;

        touchCurrentX = currentX;

        if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 10) {
            e.preventDefault();
            e.stopPropagation();

            const currentPage = getCurrentPage();
            const totalPages = getTotalPages();

            let canSwipe = false;
            if (deltaX > 0 && currentPage > 1) canSwipe = true;
            if (deltaX < 0 && currentPage < totalPages) canSwipe = true;

            if (canSwipe) {
                const limitedDelta = Math.max(-maxDragDistance, Math.min(maxDragDistance, deltaX));
                const resistance = 0.6;
                const translateX = limitedDelta * resistance;

                container.style.transform = `translateX(${translateX}px)`;
                container.style.opacity = '1';
            }
        }
    }, { passive: false });

    container.addEventListener('touchend', function(e) {
        if (!window.isMobileDevice) return;
        if (!isSwiping || isAnimating) return;

        const deltaX = touchCurrentX - touchStartX;
        const deltaY = e.changedTouches[0].pageY - touchStartY;

        isSwiping = false;

        container.style.transition = 'transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 0.2s ease';

        if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > swipeThreshold) {
            const currentPage = getCurrentPage();
            const totalPages = getTotalPages();

            if (deltaX > 0 && currentPage > 1) {
                isAnimating = true;

                container.style.transform = 'translateX(50px)';
                container.style.opacity = '0.5';

                setTimeout(() => {
                    navigateToPage(currentPage - 1);

                    setTimeout(() => {
                        container.style.transition = 'none';
                        container.style.transform = 'translateX(-50px)';
                        container.style.opacity = '0.5';

                        container.offsetHeight;

                        container.style.transition = 'transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 0.2s ease';
                        container.style.transform = 'translateX(0)';
                        container.style.opacity = '1';

                        setTimeout(() => {
                            isAnimating = false;
                        }, 300);
                    }, 50);
                }, 150);

            } else if (deltaX < 0 && currentPage < totalPages) {
                isAnimating = true;

                container.style.transform = 'translateX(-50px)';
                container.style.opacity = '0.5';

                setTimeout(() => {
                    navigateToPage(currentPage + 1);

                    setTimeout(() => {
                        container.style.transition = 'none';
                        container.style.transform = 'translateX(50px)';
                        container.style.opacity = '0.5';

                        container.offsetHeight;

                        container.style.transition = 'transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 0.2s ease';
                        container.style.transform = 'translateX(0)';
                        container.style.opacity = '1';

                        setTimeout(() => {
                            isAnimating = false;
                        }, 300);
                    }, 50);
                }, 150);

            } else {
                container.style.transform = '';
            }
        } else {
            container.style.transform = '';
        }
    }, { passive: true });

    function getCurrentPage() {
        if (typeof window.currentPage !== 'undefined') return window.currentPage;
        if (typeof currentPage !== 'undefined') return currentPage;

        const activePage = document.querySelector('.page-item.active .page-link');
        if (activePage) {
            const pageNum = parseInt(activePage.textContent);
            if (!isNaN(pageNum)) return pageNum;
        }

        return 1;
    }

    function getTotalPages() {
        if (typeof window.totalPages !== 'undefined') return window.totalPages;
        if (typeof totalPages !== 'undefined') return totalPages;

        const pageItems = document.querySelectorAll('.page-item .page-link');
        let maxPage = 1;
        pageItems.forEach(item => {
            const pageNum = parseInt(item.textContent);
            if (!isNaN(pageNum) && pageNum > maxPage) {
                maxPage = pageNum;
            }
        });

        return maxPage;
    }

    function navigateToPage(pageNum) {
        // Принудительно фиксируем overflow перед переходом
        document.body.style.overflowX = 'hidden';
        document.documentElement.style.overflowX = 'hidden';

        if (typeof window.goToPage === 'function') {
            window.goToPage(pageNum);
        } else if (typeof goToPage === 'function') {
            goToPage(pageNum);
        }

        // После перехода ещё раз применяем настройки
        setTimeout(() => {
            fixBodyOverflow();
        }, 100);
    }

    // Функция для принудительной фиксации overflow
    function fixBodyOverflow() {
        if (!window.isMobileDevice) return;

        document.body.style.overflowX = 'hidden';
        document.documentElement.style.overflowX = 'hidden';
        document.body.style.overscrollBehaviorX = 'none';
        document.documentElement.style.overscrollBehaviorX = 'none';

        console.log('✅ Overflow fixed after page transition');
    }

    // Вызываем при каждой загрузке/обновлении страницы
    window.addEventListener('pageshow', function() {
        if (window.isMobileDevice) {
            fixBodyOverflow();
        }
    });

    addSwipeStyles();
}

function addSwipeStyles() {
    if (!window.isMobileDevice) return;

    const style = document.createElement('style');
    style.setAttribute('data-swipe-styles', 'true');
    style.textContent = `
        @media (max-width: 992px) {
            /* ЖЁСТКАЯ блокировка горизонтального скролла */
            body {
                overscroll-behavior-x: none !important;
                overflow-x: hidden !important;
                position: relative !important;
                width: 100% !important;
            }
            
            html {
                overscroll-behavior-x: none !important;
                overflow-x: hidden !important;
            }
            
            /* Контейнер с карточками */
            .restaurants-container {
                touch-action: pan-y !important;
                overscroll-behavior: none !important;
                transition: transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 0.2s ease;
                will-change: transform, opacity;
            }
        }
    `;
    document.head.appendChild(style);

    // Принудительно применяем сразу
    fixBodyOverflow();
}