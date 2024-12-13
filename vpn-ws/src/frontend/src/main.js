const { app, BrowserWindow, ipcMain, Menu } = require("electron");
const { exec } = require('child_process');
const path = require("node:path");
const { Client } = require("ssh2");
const fs = require("fs");
const fsPromised = require('fs/promises');

async function delay(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function dowloadCerts({ ip, username, password }) {
  const conn = new Client();

  await fsPromised.mkdir('./certs');

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
                console.log("File is succesfully downloaded:", fileInfo.localFilePath);
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
    console.log(`Копирование сертификата: ${filename} в /usr/local/share/ca-certificates/`);
    await execCommand(copyCommand);

    console.log(`Обновление доверенных сертификатов...`);
    await execCommand(updateCommand);

    console.log('Сертификат успешно добавлен в доверенные!');
  } catch (error) {
    console.error(`Произошла ошибка: ${error.message}`);
  }
}



async function handleTryConnect(event, connectJSON) {
  const webContents = event.sender;
  const win = BrowserWindow.fromWebContents(webContents);

  // Парсим JSON с данными подключения
  let connectInfo = JSON.parse(connectJSON);
  let { ip, username, password } = connectInfo;

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
}

const createWindow = () => {
  const win = new BrowserWindow({
    width: 400,
    height: 650,
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
  Menu.setApplicationMenu(null);
  createWindow();
});
