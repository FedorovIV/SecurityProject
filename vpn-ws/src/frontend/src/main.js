const { app, BrowserWindow, ipcMain, Menu } = require("electron");
const { exec, spawn } = require("child_process");
const path = require("node:path");
const { Client } = require("ssh2");
const fs = require("fs");
const fsPromised = require("fs/promises");

let vpnProcess = null;
let subprocesses = [];

async function handleTryConnect(event, connectJSON) {
  const webContents = event.sender;
  const win = BrowserWindow.fromWebContents(webContents);

  // Парсим JSON с данными подключения
  let connectInfo = JSON.parse(connectJSON);
  let { ip, username, password, ipv6 } = connectInfo;

  try {
    const localPath = await dowloadCerts(connectInfo);
    console.log("File is available:", localPath);
  } catch (error) {
    console.error("Error caused:", error);
    win.webContents.send("error", { message: error });
  }

  try {
    await setCAcert("./certs/ca-server.crt");
  } catch (error) {
    console.error("Error caused:", error);
    win.webContents.send("error", { message: error });
  }

  try {
    // Ждём подключения VPN
    const message = await runVpnWS(ipv6);
    console.log(message);

    // Сообщаем успешное подключение
    win.webContents.send("vpn-success", { message });
  } catch (error) {
    console.error("Error caused:", error);
    win.webContents.send("error", { message: error.message });
  }
}

async function delay(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function dowloadCerts({ ip, username, password }) {
  const conn = new Client();

  const certsPath = path.join(__dirname, "certs");

  // Проверяем, существует ли папка
  if (fs.existsSync(certsPath)) {
    try {
      // Удаляем папку рекурсивно
      fs.rmSync(certsPath, { recursive: true, force: true });
      console.log("Папка ./certs успешно удалена.");
    } catch (error) {
      console.error("Ошибка удаления папки ./certs:", error);
    }
  } else {
    console.log("Папка ./certs не существует.");
  }

  await fsPromised.mkdir(certsPath);

  return new Promise((resolve, reject) => {
    conn.on("ready", () => {
      console.log("SSH connection succesful.");

      // Открываем SFTP-сессию
      conn.sftp((err, sftp) => {
        if (err) {
          reject("Error SFTP: " + err.message);
          conn.end();
          return;
        }

        const files = [
          {
            remoteFilePath: "/mnt/public-files/client.crt",
            localFilePath: "./certs/client.crt",
          },
          {
            remoteFilePath: "/mnt/public-files/client.key",
            localFilePath: "./certs/client.key",
          },
          {
            remoteFilePath: "/mnt/public-files/ca-server.crt",
            localFilePath: "./certs/ca-server.crt",
          },
        ];

        files.forEach((fileInfo) => {
          sftp.fastGet(
            fileInfo.remoteFilePath,
            fileInfo.localFilePath,
            (err) => {
              if (err) {
                reject("Dowloading file error: " + err.message);
              } else {
                console.log(
                  "File is succesfully downloaded:",
                  fileInfo.localFilePath
                );
                resolve(fileInfo.localFilePath);
              }
              conn.end();
            }
          );
        });
      });
    });

    conn.on("error", (err) => {
      reject("Error SSH: " + err.message);
    });

    conn.on("end", () => {
      console.log("SSH connection was closed");
    });

    // Устанавливаем соединение
    conn.connect({
      host: ip,
      port: 22, // Порт по умолчанию для SSH
      username: username,
      password: password,
    });
  });
}

async function setCAcert(filepath) {
  // Абсолютный путь к сертификату
  const absolutePath = path.resolve(filepath);
  const filename = path.basename(filepath);

  // Команды для копирования и обновления сертификатов
  const copyCommand = `sudo cp ${absolutePath} /usr/local/share/ca-certificates/`;
  const updateCommand = `sudo update-ca-certificates`;

  try {
    console.log(
      `Копирование сертификата: ${filename} в /usr/local/share/ca-certificates/`
    );
    await execCommand(copyCommand);

    console.log(`Обновление доверенных сертификатов...`);
    await execCommand(updateCommand);

    console.log("Сертификат успешно добавлен в доверенные!");
  } catch (error) {
    console.error(`Произошла ошибка: ${error.message}`);
  }
}

function execCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      if (stderr) {
        console.warn(stderr);
      }
      resolve(stdout);
    });
  });
}

async function runVpnWS(ipv6) {
  try {
    await execCommand("sudo ip link delete vpn-ws");
  } catch {}

  return new Promise((resolve, reject) => {
    const command = "sudo";
    const args = [
      "./vpn-ws-client",
      "--key",
      "./certs/client.key",
      "--crt",
      "./certs/client.crt",
      "--no-verify",
      "--exec",
      `ip -6 addr add ${ipv6} dev vpn-ws; ip link set dev vpn-ws up`,
      "vpn-ws",
      "--bridge",
      "wss://88.119.170.154:443/vpn",
    ];

    // Запускаем процесс через spawn
    const vpnProcess = spawn(command, args, {
      stdio: "inherit",
    });

    subprocesses.push(vpnProcess);

    // Обработчик ошибок процесса
    vpnProcess.stderr.on("data", (err) => {
      console.error("VPN Error:", err.toString());
    });

    // Если процесс завершается с ошибкой
    vpnProcess.on("error", (err) => {
      console.error("VPN Process Error:", err);
      reject(err);
    });

    // Обработчик завершения процесса (для дополнительной обработки)
    vpnProcess.on("close", (code) => {
      if (code !== 0) {
        console.error(`VPN process exited with code: ${code}`);
        reject(new Error(`VPN process exited with code: ${code}`));
      }
    });
  });
}

async function handleDisconnect() {
  try {
    await execCommand("sudo ip link delete vpn-ws");
  } catch {}
  await stopVpnWS();
}

async function stopVpnWS() {
  if (vpnProcess) {
    vpnProcess.kill("SIGKILL"); // Завершаем процесс
    vpnProcess = null; // Очищаем переменную
    console.log("VPN process has been terminated.");
  } else {
    console.log("VPN process is not running.");
  }
}

const createWindow = () => {
  const win = new BrowserWindow({
    width: 250,
    height: 450,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, "./preload.js"),
    },
  });

  // win.webContents.openDevTools()

  win.loadFile("./index.html");
};

app.whenReady().then(() => {
  ipcMain.handle("dialog:tryConnect", handleTryConnect);
  ipcMain.handle("dialog:disconnect", handleDisconnect);

  Menu.setApplicationMenu(null);
  createWindow();
});

// Обработчик закрытия главного окна
app.on("window-all-closed", () => {
  console.log("Главное окно закрыто. Завершаем дочерние процессы...");
  cleanupSubprocesses();
  if (process.platform !== "darwin") {
    app.quit();
  }
});

// Завершаем все дочерние процессы при выходе
app.on("before-quit", () => {
  console.log("Завершается приложение...");
  cleanupSubprocesses();
});

// Функция для остановки всех дочерних процессов
function cleanupSubprocesses() {
  for (const child of subprocesses) {
    if (!child.killed) {
      console.log(`Завершается процесс PID ${child.pid}`);
      child.kill(); // Завершаем процесс
    }
  }
}
