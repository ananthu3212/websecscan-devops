# WebSecScan

**WebSecScan** is a web security scanning application designed to help you identify vulnerabilities in web applications efficiently. This guide will walk you through setting up and running the project locally using Docker.

---

## **Table of Contents**

- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [Access the Application](#access-the-application)
- [Stopping the Application](#stopping-the-application)
- [Project Structure](#project-structure)
- [Notes](#notes)

---

## **Prerequisites**

Before starting, make sure you have:

- [Docker Desktop](https://www.docker.com/products/docker-desktop) installed
- Virtualization enabled in your BIOS/UEFI
- A terminal or command prompt

---

## **Setup Instructions**

1. **Open Docker Desktop**  
   Ensure Docker is running and virtualization is enabled.

2. **Choose a project directory**  
   Decide where on your computer you want to store the project.

3. **Clone the repository**  

   ```bash
   git clone https://git.w-hs.de/tobias.urban/websecscan.git
4. **Navigate into the project folder**  

   ```bash
   cd websecscan

 5.**Build and Start the Project with Docker Compose**

Docker Compose will build the necessary images and start all services defined in the `docker-compose.yml` file.

Run the following command in the terminal inside the project directory:

```bash
docker compose up --build 
```
6. **Access the Application**

Once the Docker containers are running, you can access the application in your web browser:
http://localhost:3000
- After visiting the website, you will need to register an account.  
- Please refer to the separate `REGISTRATION.md` file for detailed step-by-step instructions on account creation and email verification.

7.**Stopping the Application**

To stop the application and remove the running Docker containers, you have two options:

1. **If you started the containers in the foreground** (without `-d`), press `Ctrl + C` in the terminal where Docker Compose is running.  

2. **If you started the containers in detached mode** (with `-d`), run the following command from the project directory:

```bash
docker compose down
```
8. **Project Structure**

Here’s a high-level overview of the WebSecScan project folder layout:
websecscan/
│
├── backend/           # Server-side code and APIs
├── frontend/          # Client-side code (UI)
├── docker-compose.yml # Docker configuration for all services
├── README.md          # Project documentation
└── .env.example       # Environment variable template