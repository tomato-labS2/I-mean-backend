// DOM 요소 가져오기
const hamburgerMenu = document.querySelector('.hamburger-menu');
const sideMenu = document.getElementById('sideMenu');
const closeMenu = document.querySelector('.close-menu');
const startChatButton = document.getElementById('startChatButton');
const homeScreen = document.getElementById('homeScreen');
const chatScreen = document.getElementById('chatScreen');
const reportButton = document.querySelector('.report-button');
const reportScreen = document.getElementById('reportScreen');
const backToChatButton = document.getElementById('backToChatButton');
const chatMessages = document.getElementById('chatMessages');
const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendButton');

// 햄버거 메뉴 토글
hamburgerMenu.addEventListener('click', () => {
    sideMenu.classList.add('active');
});

closeMenu.addEventListener('click', () => {
    sideMenu.classList.remove('active');
});

// 화면 외부 클릭 시 사이드 메뉴 닫기
document.addEventListener('click', (event) => {
    if (sideMenu.classList.contains('active') &&
        !sideMenu.contains(event.target) &&
        !hamburgerMenu.contains(event.target)) {
        sideMenu.classList.remove('active');
    }
});

// 대화 시작하기 버튼 클릭
startChatButton.addEventListener('click', () => {
    homeScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    reportScreen.classList.add('hidden');
});

// 리포트 버튼 클릭
reportButton.addEventListener('click', () => {
    homeScreen.classList.add('hidden');
    chatScreen.classList.add('hidden');
    reportScreen.classList.remove('hidden');
});

// 대화로 돌아가기 버튼 클릭
backToChatButton.addEventListener('click', () => {
    reportScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
});

// 메시지 전송 처리
function sendMessage() {
    const messageText = messageInput.value.trim();
    if (messageText === '') return;

    // 현재 시간 가져오기
    const now = new Date();
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const timeString = `${hours}:${minutes}`;

    // 사용자 메시지 추가
    addMessage('user', messageText, timeString);

    // 입력창 비우기
    messageInput.value = '';

    // 스크롤을 가장 아래로 이동
    scrollToBottom();

    // 여기에 AI 응답 로직 추가 (예시로 타이머 사용)
    setTimeout(() => {
        // 상대방 응답 (예시)
        if (Math.random() > 0.5) {
            addMessage('partner', '나는 그렇게 생각하지 않아요.', timeString);
        }

        // 상담사 응답 (예시)
        setTimeout(() => {
            let counselorResponse = '';
            if (messageText.includes('화가')) {
                counselorResponse = '화가 나는 상황에서는 감정을 인정하고 숨을 깊게 쉬어보는 것이 도움이 될 수 있어요. 서로의 관점을 이해하려고 노력해 보세요.';
            } else if (messageText.includes('미안')) {
                counselorResponse = '사과의 말을 하는 것은 관계를 회복하는 중요한 단계입니다. 서로의 감정을 인정하고 더 나은 방향으로 나아가보세요.';
            } else {
                counselorResponse = '서로의 의견을 존중하면서 대화를 이어가는 것이 중요합니다. 어떤 부분에서 의견 차이가 있나요?';
            }
            addMessage('counselor', counselorResponse, timeString);
            scrollToBottom();
        }, 1000);
    }, 800);
}

// 메시지 추가 함수
function addMessage(type, text, time) {
    const messageContainer = document.createElement('div');
    messageContainer.className = `message-container ${type}`;

    const messageBubble = document.createElement('div');
    messageBubble.className = 'message-bubble';
    messageBubble.textContent = text;

    const messageTime = document.createElement('div');
    messageTime.className = 'message-time';
    messageTime.textContent = time;

    messageContainer.appendChild(messageBubble);
    messageContainer.appendChild(messageTime);
    chatMessages.appendChild(messageContainer);
}

// 스크롤을 가장 아래로 이동하는 함수
function scrollToBottom() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// 전송 버튼 클릭 이벤트
sendButton.addEventListener('click', sendMessage);

// 엔터 키 이벤트
messageInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        sendMessage();
    }
});

// 로드 시 모든 아이콘이 정상적으로 보이도록 Font Awesome 폴백 설정
document.addEventListener('DOMContentLoaded', () => {
    if (!window.FontAwesome) {
        console.warn('Font Awesome is not loaded properly.');
    }
});
