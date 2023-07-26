
const galleryContainer = document.querySelector('.gallery');
const mainContainer = document.querySelector('.main');

let currentImageIndex = 0;
const images = galleryContainer.querySelectorAll('.gallery-img');

function showImage(index) {
  const fullImage = document.createElement('img');
  fullImage.classList.add('full-img');
  fullImage.src = images[index].src;

  const overlay = document.createElement('div');
  overlay.classList.add('overlay');

  overlay.appendChild(fullImage);
  mainContainer.appendChild(overlay);

  overlay.addEventListener('click', () => {
    mainContainer.removeChild(overlay);
  });
}

galleryContainer.addEventListener('click', (event) => {
  if (event.target.classList.contains('gallery-img')) {
    currentImageIndex = Array.from(images).indexOf(event.target);
    showImage(currentImageIndex);
  }
});

document.querySelector('.prev-btn').addEventListener('click', () => {
  currentImageIndex = (currentImageIndex - 1 + images.length) % images.length;
  showImage(currentImageIndex);
});

document.querySelector('.next-btn').addEventListener('click', () => {
  currentImageIndex = (currentImageIndex + 1) % images.length;
  showImage(currentImageIndex);
});

