// Проверяем, не на странице ли ошибки мы находимся
if (document.querySelector('.error-page')) {
    console.log('🛑 Detected error page - disabling header scroll');
    // Заменяем initHeaderScroll на пустую функцию
    window.initHeaderScroll = function() {};
}

// ==================== ОСНОВНЫЕ ПЕРЕМЕННЫЕ ====================
let currentCategory = window.currentCategory;
let currentPage = window.currentPage || 1;
let totalPages = window.totalPages || 1;
let isLoading = false;
let currentSort = 'default';
let allPlaces = [];
let isInitialLoad = true;
let userLocation = null;

// Элементы DOM
const navbar = document.querySelector('.navbar');
const smartPagination = document.querySelector('.smart-pagination');

// ==================== ИНИЦИАЛИЗАЦИЯ ====================
document.addEventListener('DOMContentLoaded', function() {
    console.log('Инициализация страницы...');

    // Восстанавливаем последний фильтр
    const lastFilter = localStorage.getItem('lastSortFilter');
    const sortFilter = document.getElementById('sortFilter');
    if (lastFilter && sortFilter) {
        sortFilter.value = lastFilter;
        currentSort = lastFilter;
        console.log('Восстановлен фильтр:', lastFilter);
    }

    loadAllPlaces();
    initFilters();
    initPagination(totalPages, currentPage);
    initScrollSystem();
    initHeaderScroll();
    initFavorites();

    // ЗАПРАШИВАЕМ ГЕОЛОКАЦИЮ СРАЗУ ПРИ ЗАГРУЗКЕ
    setTimeout(() => {
        getUserLocation().catch(() => getLocationByIP())
        .then(location => {
            console.log('🎉 Геолокация готова к использованию!');

            // АВТОМАТИЧЕСКИ ПРИМЕНЯЕМ ФИЛЬТР ЕСЛИ ОН ВЫБРАН
            if (currentSort === 'distance') {
                console.log('🔄 Автоматически применяем фильтр расстояния...');
                setTimeout(() => {
                    applySortingToAll();
                }, 500);
            }
        }).catch(error => {
            console.log('Геолокация не доступна, но фильтры работают');
        });
    }, 1000);
});

// ==================== ЗАГРУЗКА ДАННЫХ ====================
async function loadAllPlaces() {
    showLoading();

    try {
        console.log(`🎯 Загрузка данных для категории: ${currentCategory}`);
        const allPlacesData = [];

        // Загружаем данные ТОЛЬКО для текущей категории
        const response = await fetch(`/api/categories/${currentCategory}?page=1`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.places && data.places.length > 0) {
            console.log(`✅ Загружено ${data.places.length} заведений для категории ${currentCategory}`);

            data.places.forEach(place => {
                // ВАЖНО: Проверяем что заведение принадлежит текущей категории
                if (place.category_en === currentCategory) {
                    allPlacesData.push({
                        id: place.id,
                        title: place.title,
                        description: place.description,
                        telephone: place.telephone,
                        address: place.address,
                        image_path: place.image_path,
                        slug: place.slug,
                        category_en: place.category_en,  // Добавляем категорию!
                        avg_rating: place.avg_rating || 0,
                        name: (place.title || '').toLowerCase(),
                        latitude: place.latitude,
                        longitude: place.longitude
                    });
                } else {
                    console.warn(`🚫 Пропускаем заведение из другой категории: ${place.title} (${place.category_en})`);
                }
            });
        }

        allPlaces = allPlacesData;
        const perPage = 10; // Столько же заведений на странице как на сервере
        totalPages = Math.ceil(allPlacesData.length / perPage);

        console.log(`✅ Итог: ${allPlaces.length} заведений в категории ${currentCategory}`);

        renderCurrentPage();
        initPagination(totalPages, currentPage);
        hideLoading();

    } catch (error) {
        console.error('❌ Ошибка загрузки:', error);
        hideLoading();
        alert(`Ошибка загрузки категории ${currentCategory}: ${error.message}`);
    }
}