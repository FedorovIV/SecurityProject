
document.querySelector('.submit-button').addEventListener('click', async (event)=>{
    event.preventDefault();
    if (document.querySelector('.submit-button').classList.contains('_connected')){
        handleDisconnect();
    } else {
        handleTryConnect();
    }

})

async function handleTryConnect(){
    let ip = document.querySelector('#ip').value;
    let username = document.querySelector('#username').value;
    let password = document.querySelector('#password').value;

    document.querySelector('.submit-button').classList.add('_try-connect');
    document.querySelector('.submit-button__text').textContent = 'Подключение';

    await window.electronAPI.tryConnect(JSON.stringify({ip, username, password}));

    document.querySelector('.submit-button').classList.remove('_try-connect');
    document.querySelector('.submit-button').classList.add('_connected');
    document.querySelector('.submit-button__text').textContent = 'Подключено';
}

async function handleDisconnect() {
    document.querySelector('.submit-button').classList.remove('_connected');
    document.querySelector('.submit-button__text').textContent = 'Подключиться';
}