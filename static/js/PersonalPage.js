// ==================== Глобальные переменные и константы ====================
// В начале вашего JavaScript:
const PATHS = {
    starActive: "{{ url_for('static', filename='Фотки зданий/baka.png') }}",
    starInactive: "{{ url_for('static', filename='Фотки зданий/star.png') }}",
    avatar: "{{ url_for('static', filename='Фотки зданий/avatar.png') }}"
};

let reviews = [];
let overallRating = 0;
let ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
let currentFilter = 0;
let selectedRating = 0;
let likeCount = 0;
let dislikeCount = 0;

// ==================== Функции для работы с карточкой ====================
function flipCard() {
    document.querySelector('.image-flip-container').classList.toggle('flipped');
}

function expandImage(btn) {
    const img = btn.closest('.image-front').querySelector('img');
    const imgSrc = img.src;

    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100%';
    overlay.style.height = '100%';
    overlay.style.backgroundColor = 'rgba(0,0,0,0.6)';
    overlay.style.display = 'flex';
    overlay.style.justifyContent = 'center';
    overlay.style.alignItems = 'center';
    overlay.style.zIndex = '1000';
    overlay.style.cursor = 'zoom-out';

    const expandedImg = document.createElement('img');
    expandedImg.src = imgSrc;
    expandedImg.style.maxWidth = '90%';
    expandedImg.style.maxHeight = '90%';
    expandedImg.style.objectFit = 'contain';

    overlay.appendChild(expandedImg);
    overlay.onclick = function() {
        document.body.removeChild(overlay);
    };

    document.body.appendChild(overlay);
}

// ==================== Инициализация карты ====================
(function(e,t){
    var r=document.getElementById(e);
    r.contentWindow.document.open(),
    r.contentWindow.document.write(atob(t)),
    r.contentWindow.document.close()
})("map_547336407", "PGJvZHk+PHN0eWxlPgogICAgICAgIGh0bWwsIGJvZHkgewogICAgICAgICAgICBtYXJnaW46IDA7CiAgICAgICAgICAgIHBhZGRpbmc6IDA7CiAgICAgICAgfQogICAgICAgIGh0bWwsIGJvZHksICNtYXAgewogICAgICAgICAgICB3aWR0aDogMTAwJTsKICAgICAgICAgICAgaGVpZ2h0OiAxMDAlOwogICAgICAgIH0KICAgICAgICAuYnVsbGV0LW1hcmtlciB7CiAgICAgICAgICAgIHdpZHRoOiAyMHB4OwogICAgICAgICAgICBoZWlnaHQ6IDIwcHg7CiAgICAgICAgICAgIGJveC1zaXppbmc6IGJvcmRlci1ib3g7CiAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6ICNmZmY7CiAgICAgICAgICAgIGJveC1zaGFkb3c6IDAgMXB4IDNweCAwIHJnYmEoMCwgMCwgMCwgMC4yKTsKICAgICAgICAgICAgYm9yZGVyOiA0cHggc29saWQgIzAyODFmMjsKICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgICAgIH0KICAgICAgICAucGVybWFuZW50LXRvb2x0aXAgewogICAgICAgICAgICBiYWNrZ3JvdW5kOiBub25lOwogICAgICAgICAgICBib3gtc2hhZG93OiBub25lOwogICAgICAgICAgICBib3JkZXI6IG5vbmU7CiAgICAgICAgICAgIHBhZGRpbmc6IDZweCAxMnB4OwogICAgICAgICAgICBjb2xvcjogIzI2MjYyNjsKICAgICAgICB9CiAgICAgICAgLnBlcm1hbmVudC10b29sdGlwOmJlZm9yZSB7CiAgICAgICAgICAgIGRpc3BsYXk6IG5vbmU7CiAgICAgICAgfQogICAgICAgIC5kZy1wb3B1cF9oaWRkZW5fdHJ1ZSB7CiAgICAgICAgICAgIGRpc3BsYXk6IGJsb2NrOwogICAgICAgIH0KICAgICAgICAubGVhZmxldC1jb250YWluZXIgLmxlYWZsZXQtcG9wdXAgLmxlYWZsZXQtcG9wdXAtY2xvc2UtYnV0dG9uIHsKICAgICAgICAgICAgdG9wOiAwOwogICAgICAgICAgICByaWdodDogMDsKICAgICAgICAgICAgd2lkdGg6IDIwcHg7CiAgICAgICAgICAgIGhlaWdodDogMjBweDsKICAgICAgICAgICAgZm9udC1zaXplOiAyMHB4OwogICAgICAgICAgICBsaW5lLWhlaWdodDogMTsKICAgICAgICB9CiAgICA8L3N0eWxlPjxkaXYgaWQ9Im1hcCI+PC9kaXY+PHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiIHNyYz0iaHR0cHM6Ly9tYXBzLmFwaS4yZ2lzLnJ1LzIuMC9sb2FkZXIuanM/cGtnPWZ1bGwmYW1wO3NraW49bGlnaHQiPjwvc2NyaXB0PjxzY3JpcHQ+KGZ1bmN0aW9uKGUpe3ZhciB0PUpTT04ucGFyc2UoZSkscj10Lm9yZGVyZWRHZW9tZXRyaWVzLG49dC5tYXBQb3NpdGlvbixhPXQuaXNXaGVlbFpvb21FbmFibGVkO2Z1bmN0aW9uIG8oZSl7cmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudChhdG9iKGUpLnNwbGl0KCIiKS5tYXAoZnVuY3Rpb24oZSl7cmV0dXJuIiUiKygiMDAiK2UuY2hhckNvZGVBdCgwKS50b1N0cmluZygxNikpLnNsaWNlKC0yKX0pLmpvaW4oIiIpKX1ERy50aGVuKGZ1bmN0aW9uKCl7dmFyIGU9REcubWFwKCJtYXAiLHtjZW50ZXI6W24ubGF0LG4ubG9uXSx6b29tOm4uem9vbSxzY3JvbGxXaGVlbFpvb206YSx6b29tQ29udHJvbDohYX0pO0RHLmdlb0pTT04ocix7c3R5bGU6ZnVuY3Rpb24oZSl7dmFyIHQscixuLGEsbztyZXR1cm57ZmlsbENvbG9yOm51bGw9PT0odD1lKXx8dm9pZCAwPT09dD92b2lkIDA6dC5wcm9wZXJ0aWVzLmZpbGxDb2xvcixmaWxsT3BhY2l0eTpudWxsPT09KHI9ZSl8fHZvaWQgMD09PXI/dm9pZCAwOnIucHJvcGVydGllcy5maWxsT3BhY2l0eSxjb2xvcjpudWxsPT09KG49ZSl8fHZvaWQgMD09PW4/dm9pZCAwOm4ucHJvcGVydGllcy5zdHJva2VDb2xvcix3ZWlnaHQ6bnVsbD09PShhPWUpfHx2b2lkIDA9PT1hP3ZvaWQgMDphLnByb3BlcnRpZXMuc3Ryb2tlV2lkdGgsb3BhY2l0eTpudWxsPT09KG89ZSl8fHZvaWQgMD09PW8/dm9pZCAwOm8ucHJvcGVydGllcy5zdHJva2VPcGFjaXR5fX0scG9pbnRUb0xheWVyOmZ1bmN0aW9uKGUsdCl7cmV0dXJuInJhZGl1cyJpbiBlLnByb3BlcnRpZXM/REcuY2lyY2xlKHQsZS5wcm9wZXJ0aWVzLnJhZGl1cyk6REcubWFya2VyKHQse2ljb246ZnVuY3Rpb24oZSl7cmV0dXJuIERHLmRpdkljb24oe2h0bWw6IjxkaXYgY2xhc3M9J2J1bGxldC1tYXJrZXInIHN0eWxlPSdib3JkZXItY29sb3I6ICIrZSsiOyc+PC9kaXY+IixjbGFzc05hbWU6Im92ZXJyaWRlLWRlZmF1bHQiLGljb25TaXplOlsyMCwyMF0saWNvbkFuY2hvcjpbMTAsMTBdfSl9KGUucHJvcGVydGllcy5jb2xvcil9KX0sb25FYWNoRmVhdHVyZTpmdW5jdGlvbihlLHQpe2UucHJvcGVydGllcy5kZXNjcmlwdGlvbiYtdC5iaW5kUG9wdXAobyhlLnByb3BlcnRpZXMuZGVzY3JpcHRpb24pLHtjbG9zZUJ1dHRvbjohMCxjbG9zZU9uRXNjYXBlS2V5OiEwfSksZS5wcm9wZXJ0aWVzLnRpdGxlJiZ0LmJpbmRUb29sdGlwKG8oZS5wcm9wZXJ0aWVzLnRpdGxlKSx7cGVybWFuZW50OiEwLG9wYWNpdHk6MSxjbGFzc05hbWU6InBlcm1hbmVudC10b29sdGlwIn0pfX0pLmFkZFRvKGUpfSl9KSgneyJvcmRlcmVkR2VvbWV0cmllcyI6W3sidHlwZSI6IkZlYXR1cmUiLCJwcm9wZXJ0aWVzIjp7ImNvbG9yIjoiIzAwMDAwMCIsInRpdGxlIjoiMEpIUXNOR0EwTERSaU5DNjBMZz0iLCJkZXNjcmlwdGlvbiI6IlBIQSswS0RRdGRHQjBZTFF2dEdBMExEUXZTRENxOUNSMExEUmdOQ3cwWWpRdXRDNHdyc2cwTC9SZ05DMTBMVFF1OUN3MExQUXNOQzEwWUlnMFlIUXN0QyswTGpRdkNEUXM5QyswWUhSZ3RHUDBMd2cwTEhRdTlHTzBMVFFzQ0RRczlHQTBZUFF0OUM0MEwzUmdkQzYwTDdRdVNEUXV0R0QwWVhRdmRDNExDRFF2OUdBMExqUXM5QyswWUxRdnRDeTBMdlF0ZEM5MEwzUmk5QzFJTkMvMEw0ZzBZTFJnTkN3MExUUXVOR0cwTGpRdnRDOTBMM1JpOUM4SU5HQTBMWFJodEMxMEwvUmd0Q3cwTHd1UEM5d1BnPT0iLCJ6SW5kZXgiOjEwMDAwMDAwMDB9LCJnZW9tZXRyeSI6eyJ0eXBlIjoiUG9pbnQiLCJjb29yZGluYXRlcyI6WzMxLjIzOTgwMyw1OC41MzE3MzNdfSwiaWQiOjczMX1dLCJtYXBQb3NpdGlvbiI6eyJsYXQiOjU4LjUzMTY3NjIxMDAwNzg2LCJsb24iOjMxLjI0MTk4NDM2NzM3MDYwNSwiem9vbSI6MTZ9LCJpc1doZWVsWm9vbUVuYWJsZWQiOnRydWV9Jyk8L3NjcmlwdD48c2NyaXB0IGFzeW5jPSIiIHNyYz0iaHR0cHM6Ly93d3cuZ29vZ2xldGFnbWFuYWdlci5jb20vZ3RhZy9qcz9pZD1HLVQ4NktNRDAzQzciPjwvc2NyaXB0PjxzY3JpcHQgaWQ9Imdvb2dsZS1hbmFseXRpY3MiPgogICAgICB3aW5kb3cuZGF0YUxheWVyID0gd2luZG93LmRhdGFMYXllciB8fCBbXTsKICAgICAgZnVuY3Rpb24gZ3RhZygpe2RhdGFMYXllci5wdXNoKGFyZ3VtZW50cyk7fQogICAgICBndGFnKCdqcycsIG5ldyBEYXRlKCkpOwogICAgICBndGFnKCdjb25maWcnLCAnRy1UODZLTUQwM0M3JywgeyJjb29raWVfZmxhZ3MiOiJTYW1lU2l0ZT1Ob25lOyBTZWN1cmU7IFBhcnRpdGlvbmVkIiwiY29va2llX3VwZGF0ZSI6ZmFsc2V9KTsKICAgICAgdHJ1ZSAmJiBndGFnKCdldmVudCcsICdmcm9tX2lmcmFtZScpOwogICAgPC9zY3JpcHQ+PC9ib2R5Pg==");

// ==================== Функции для модальных окон ====================
// Меню
function openMenuModal() {
    document.getElementById('menu-modal').style.display = 'flex';
}

function closeMenuModal() {
    document.getElementById('menu-modal').style.display = 'none';
}

// Отзывы
function openReviewModal() {
    document.getElementById('review-modal').style.display = 'flex';
}

function closeReviewModal() {
    document.getElementById('review-modal').style.display = 'none';
}

// Полный отзыв
function openFullReviewModal(reviewId) {
    const review = reviews.find(r => r.id == reviewId);
    if (!review) return;

    const modal = document.getElementById('full-review-modal');
    const commentElement = modal.querySelector('.review-comment');

    modal.style.display = 'none';
    void modal.offsetHeight;

    modal.querySelector('.review-name').textContent = review.name;
    modal.querySelector('.review-rating').innerHTML =
        `<img src="${PATHS.starActive}" alt="★">`.repeat(review.rating) +
        `<img src="${PATHS.starInactive}" alt="★">`.repeat(5 - review.rating);

    commentElement.innerHTML = review.comment.replace(/\n/g, '<br>');
    commentElement.style.maxHeight = '';
    commentElement.style.overflowY = '';
    void commentElement.offsetHeight;

    const containerHeight = 370;
    commentElement.style.maxHeight = `${containerHeight}px`;
    commentElement.style.overflowY = 'auto';

    modal.querySelector('.like-count').textContent = review.likes;
    modal.querySelector('.dislike-count').textContent = review.dislikes;

    const likeBtn = modal.querySelector('.like-btn');
    const dislikeBtn = modal.querySelector('.dislike-btn');
    likeBtn.disabled = review.userVoted === 'like';
    dislikeBtn.disabled = review.userVoted === 'dislike';

    modal.dataset.reviewId = reviewId;
    modal.style.display = 'flex';
}

function closeFullReviewModal() {
    document.getElementById('full-review-modal').style.display = 'none';
}

// ==================== Функции для работы с отзывами ====================
function filterReviewsByRating(rating) {
    const reviewList = document.getElementById('review-list');
    const reviewCards = reviewList.querySelectorAll('.review-card');
    let hasMatches = false;

    const oldMsg = document.getElementById('no-reviews-message');
    if (oldMsg) oldMsg.remove();

    reviewCards.forEach(card => {
        const cardRating = parseInt(card.querySelector('.rating').dataset.rating);
        if (rating === 0 || cardRating === rating) {
            card.style.display = 'flex';
            hasMatches = true;
        } else {
            card.style.display = 'none';
        }
    });

    if (!hasMatches && rating !== 0) {
        const msg = document.createElement('div');
        msg.id = 'no-reviews-message';
        msg.textContent = 'Таких отзывов нет!';
        msg.style.textAlign = 'center';
        msg.style.padding = '20px';
        msg.style.color = '#666';
        reviewList.appendChild(msg);
    }

    setTimeout(updateReviewVisibility, 50);
}

function showAllReviews() {
    currentFilter = 0;
    filterStars.forEach(star => {
        star.innerHTML = `<img src="${PATHS.starInactive}" alt="★">`;
    });
    filterReviewsByRating(0);
}

function updateOverallRating() {
    const totalReviews = reviews.length;
    if (totalReviews === 0) {
        overallRating = 0;
    } else {
        const totalRating = reviews.reduce((sum, review) => sum + review.rating, 0);
        overallRating = (totalRating / totalReviews).toFixed(1);
    }

    document.getElementById('overall-rating').textContent = overallRating;
    document.getElementById('total-reviews').textContent = totalReviews;
    updateRatingBars();
}

function updateRatingBars() {
    const totalReviews = reviews.length;
    for (let i = 1; i <= 5; i++) {
        const count = ratingCounts[i];
        const percentage = totalReviews === 0 ? 0 : (count / totalReviews) * 100;
        const bar = document.querySelector(`.rating-bar:nth-child(${6 - i}) .fill`);
        const countSpan = document.querySelector(`.rating-bar:nth-child(${6 - i}) span:last-child`);
        bar.style.width = `${percentage}%`;
        countSpan.textContent = count;
    }
}

function limitCommentHeight(reviewElement) {
    const container = reviewElement.querySelector('.comment-container');
    const textElement = reviewElement.querySelector('.comment-text');
    const blurElement = reviewElement.querySelector('.comment-blur');
    const expandButton = reviewElement.querySelector('.expand');

    expandButton.style.display = 'block';

    if (!textElement.textContent.trim()) {
        container.style.display = 'none';
        if (blurElement) blurElement.style.display = 'none';
        return;
    }

    const lineHeight = parseInt(getComputedStyle(textElement).lineHeight);
    const maxHeight = lineHeight * 5;

    if (textElement.scrollHeight > maxHeight) {
        container.style.maxHeight = `${maxHeight}px`;
        if (blurElement) blurElement.style.display = 'block';
    } else {
        container.style.maxHeight = 'none';
        if (blurElement) blurElement.style.display = 'none';
    }
}

// ==================== Функции для работы с рейтингом ====================
function likeReview() {
    likeCount++;
    document.getElementById('like-count').textContent = likeCount;
}

function dislikeReview() {
    dislikeCount++;
    document.getElementById('dislike-count').textContent = dislikeCount;
}

function rateReview(isLike) {
    const modal = document.getElementById('full-review-modal');
    const reviewId = modal.dataset.reviewId;
    const review = reviews.find(r => r.id == reviewId);

    if (!review) return;

    if (review.userVoted) {
        if (review.userVoted === 'like') {
            review.likes--;
        } else {
            review.dislikes--;
        }

        if ((isLike && review.userVoted === 'like') || (!isLike && review.userVoted === 'dislike')) {
            review.userVoted = null;
        } else {
            if (isLike) {
                review.likes++;
                review.userVoted = 'like';
            } else {
                review.dislikes++;
                review.userVoted = 'dislike';
            }
        }
    } else {
        if (isLike) {
            review.likes++;
            review.userVoted = 'like';
        } else {
            review.dislikes++;
            review.userVoted = 'dislike';
        }
    }

    modal.querySelector('.like-count').textContent = review.likes;
    modal.querySelector('.dislike-count').textContent = review.dislikes;

    const likeBtn = modal.querySelector('.like-btn');
    const dislikeBtn = modal.querySelector('.dislike-btn');
    likeBtn.disabled = review.userVoted === 'like';
    dislikeBtn.disabled = review.userVoted === 'dislike';

    const likeImg = likeBtn.querySelector('img');
    const dislikeImg = dislikeBtn.querySelector('img');

    if (review.userVoted === 'like') {
        dislikeImg.style.opacity = '1';
        likeImg.style.opacity = '0.5';
    } else if (review.userVoted === 'dislike') {
        dislikeImg.style.opacity = '0.5';
        likeImg.style.opacity = '1';
    } else {
        dislikeImg.style.opacity = '0.5';
        likeImg.style.opacity = '0.5';
    }
}

// ==================== Функции для прокрутки отзывов ====================
function scrollReviews(direction) {
    const reviewList = document.getElementById('review-list');
    const scrollAmount = 300;

    if (direction === 'left' && reviewList.scrollLeft > 0) {
        reviewList.scrollBy({ left: -scrollAmount, behavior: 'smooth' });
    } else if (direction === 'right' && reviewList.scrollLeft + reviewList.clientWidth < reviewList.scrollWidth) {
        reviewList.scrollBy({ left: scrollAmount, behavior: 'smooth' });
    }
}

function updateReviewVisibility() {
    const reviewList = document.getElementById('review-list');
    const visibleReviews = Array.from(reviewList.querySelectorAll('.review-card'))
        .filter(card => window.getComputedStyle(card).display !== 'none');

    const leftButton = document.querySelector('.scroll-button.left');
    const rightButton = document.querySelector('.scroll-button.right');

    const canScrollLeft = reviewList.scrollLeft > 0;
    const canScrollRight = reviewList.scrollLeft + reviewList.clientWidth < reviewList.scrollWidth;

    if (visibleReviews.length === 0) {
        leftButton.style.opacity = '0';
        leftButton.style.pointerEvents = 'none';
        rightButton.style.opacity = '0';
        rightButton.style.pointerEvents = 'none';
    } else {
        leftButton.style.opacity = canScrollLeft ? '1' : '0.5';
        leftButton.style.pointerEvents = canScrollLeft ? 'auto' : 'none';

        rightButton.style.opacity = canScrollRight ? '1' : '0.5';
        rightButton.style.pointerEvents = canScrollRight ? 'auto' : 'none';
    }
}

// ==================== Обработчики событий ====================
// Закрытие модальных окон
document.getElementById('review-modal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeReviewModal();
    }
});

document.getElementById('full-review-modal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeFullReviewModal();
    }
});

// Обработчик отправки формы отзыва
const reviewForm = document.getElementById('review-form');
const reviewList = document.getElementById('review-list');
reviewForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = document.getElementById('name').value;
    const comment = document.getElementById('comment').value;

    if (selectedRating === 0) {
        document.getElementById('rating-error').style.display = 'inline';
        return;
    } else {
        document.getElementById('rating-error').style.display = 'none';
    }

    const review = {
        id: Date.now(),
        name: name,
        rating: selectedRating,
        comment: comment,
        likes: 0,
        dislikes: 0,
        userVoted: null
    };

    reviews.push(review);
    ratingCounts[Math.floor(selectedRating)]++;
    updateOverallRating();

    const reviewElement = document.createElement('div');
    reviewElement.className = 'review-card highlight';
    reviewElement.dataset.reviewId = review.id;

    reviewElement.innerHTML = `
        <div class="review-header">
            <img class="avatar" src="${PATHS.avatar}" alt="Аватар">
            <div class="name-rating">
                <div class="name">${name}</div>
                <div class="rating" data-rating="${selectedRating}">
                    ${`<img src="${PATHS.starActive}" alt="★" style="width:20px;height:20px;">`.repeat(selectedRating)}
                    ${`<img src="${PATHS.starInactive}" alt="★" style="width:20px;height:20px;">`.repeat(5 - selectedRating)}
                </div>
            </div>
        </div>
        <div class="comment-container">
            <div class="comment-text">${comment || ''}</div>
            ${comment ? '<div class="comment-blur"></div>' : ''}
        </div>
        <div class="expand" onclick="openFullReviewModal(${review.id})">Развернуть</div>
    `;

    reviewList.prepend(reviewElement);
    if (comment) {
        limitCommentHeight(reviewElement);
    }
    updateReviewVisibility();

    reviewList.scrollTo({ left: 0, behavior: 'smooth' });

    reviewForm.reset();
    stars.forEach(star => star.innerHTML = `<img src="{{ url_for('static', filename='Фотки зданий/star.png') }}" alt="★" style="width: 24px; height: 24px;">`);
    selectedRating = 0;
    closeReviewModal();
    updateReviewVisibility();
});

// Обработчики звёзд рейтинга
const stars = document.querySelectorAll('#review-stars .star');
stars.forEach(star => {
    star.addEventListener('click', () => {
        const value = parseFloat(star.getAttribute('data-value'));
        selectedRating = value;

        stars.forEach((s, index) => {
            const starValue = parseFloat(s.getAttribute('data-value'));
            if (starValue <= value) {
                s.innerHTML = `<img src="{{ url_for('static', filename='Фотки зданий/baka.png') }}" alt="★" style="width: 24px; height: 24px;">`;
            } else {
                s.innerHTML = `<img src="{{ url_for('static', filename='Фотки зданий/star.png') }}" alt="★" style="width: 24px; height: 24px;">`;
            }
        });
    });
});

// Обработчики звёзд фильтра
const filterStars = document.querySelectorAll('#filter-stars .star');
filterStars.forEach(star => {
    star.addEventListener('click', function() {
        const value = parseInt(this.getAttribute('data-value'));

        if (currentFilter === value) {
            currentFilter = 0;
            filterStars.forEach(s => {
                s.innerHTML = `<img src="${PATHS.starInactive}" alt="★">`;
            });
        } else {
            currentFilter = value;
            filterStars.forEach((s, index) => {
                const starValue = index + 1;
                s.innerHTML = `<img src="${starValue <= value ? PATHS.starActive : PATHS.starInactive}" alt="★">`;
            });
        }

        filterReviewsByRating(currentFilter);
    });
});

// Прокрутка отзывов
reviewList.addEventListener('scroll', function() {
    const leftButton = document.querySelector('.scroll-button.left');
    const rightButton = document.querySelector('.scroll-button.right');

    const canScrollLeft = this.scrollLeft > 0;
    const canScrollRight = this.scrollLeft + this.clientWidth < this.scrollWidth;

    leftButton.style.opacity = canScrollLeft ? '1' : '0.5';
    leftButton.style.pointerEvents = canScrollLeft ? 'auto' : 'none';

    rightButton.style.opacity = canScrollRight ? '1' : '0.5';
    rightButton.style.pointerEvents = canScrollRight ? 'auto' : 'none';
});

// ==================== Инициализация при загрузке ====================
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('full-review-modal').style.display = 'none';

    const favoriteBtn = document.querySelector('.favorite-btn');
    const restaurantId = favoriteBtn.getAttribute('data-id');

    if (localStorage.getItem('favorites')) {
        const favorites = JSON.parse(localStorage.getItem('favorites'));
        if (favorites.includes(restaurantId)) {
            favoriteBtn.classList.add('active');
        }
    }
});