const mysql2 = require("mysql2/promise");  // Use promise version of mysql2
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const nodemailer = require("nodemailer");
const twilio = require("twilio");
const puppeteer = require("puppeteer");
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Set static folder
const publicDir = path.join(__dirname, "../public");
app.use(express.static(publicDir));
app.use("/css", express.static(path.join(publicDir, "css")));
app.use("/images", express.static(path.join(publicDir, "images")));
app.use("/scripts", express.static(path.join(publicDir, "scripts")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use(cookieParser());
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  })
);

// Create a pool
const pool = mysql2.createPool({
  host: "srv1458.hstgr.io",
  user: "u691495308_admin",
  password: "Admin@mayada1",
  database: "u691495308_MayadaAcademy",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Wrapper function for database queries
async function queryDatabase(sql, params) {
  const [results, ] = await pool.execute(sql, params);
  return results;
}

// Firebase Admin SDK
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware
async function isAuthenticated(req, res, next) {
  const idToken = req.headers.authorization && req.headers.authorization.split("Bearer ")[1];
  if (!idToken) {
    return res.redirect("/login");
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.session.userId = decodedToken.uid;
    req.session.userRole = decodedToken.role || "user";
    next();
  } catch (error) {
    res.redirect("/login");
  }
}

const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: "zeyadsattar.me@gmail.com",
    pass: "roet gfno jiuu tkif",
  },
});

// Twilio client setup
const accountSid = "AC0c4eb3a11c12b58dd60f0f3e07edd19b";
const authToken = "90cd6d0451c0dae5a3954e106b62a09b";
const client = twilio(accountSid, authToken);

const getChromeExecutablePath = async () => {
  if (process.env.CHROME_EXECUTABLE_PATH) {
    return process.env.CHROME_EXECUTABLE_PATH;
  }

  try {
    const chromeLauncher = await import('chrome-launcher');
    const chromePath = await chromeLauncher.Launcher.getInstallations();
    if (chromePath.length > 0) {
      return chromePath[0];
    }
  } catch (err) {
    console.error('Error detecting Chrome path:', err);
  }

  return 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
};

// Function to send WhatsApp messages
const sendWhatsAppMessages = async (numbersAndMessages) => {
  const chromePath = await getChromeExecutablePath();

  const browser = await puppeteer.launch({
    headless: false,
    executablePath: chromePath
  });

  const page = await browser.newPage();
  await page.goto('https://web.whatsapp.com');

  console.log('Waiting for QR code to be scanned...');
  await page.waitForSelector('canvas', { timeout: 60000 });
  await page.waitForFunction(
    'document.querySelector("canvas") === null',
    { timeout: 600000 }
  );
  console.log('QR code scanned.');

  for (const { phone, message } of numbersAndMessages) {
    const formattedPhone = phone.replace(/^\+/, '');
    const encodedMessage = encodeURIComponent(message);
    const url = `https://web.whatsapp.com/send?phone=${formattedPhone}&text=${encodedMessage}`;
    console.log(`Navigating to: ${url}`);
    await page.goto(url);

    try {
      await page.waitForSelector('div[contenteditable="true"][data-tab="6"]', { timeout: 60000 });
      const inputArea = await page.$('div[contenteditable="true"][data-tab="6"]');
      await inputArea.focus();
      await page.keyboard.type(message, { delay: 100 });
      await page.keyboard.press('Enter');
      console.log(`Message sent to ${formattedPhone}`);
      await page.waitForTimeout(5000);
    } catch (error) {
      console.error(`Error sending message to ${formattedPhone}:`, error);
    }
  }

  await browser.close();
};

app.post("/send-all-parents-messages", async (req, res) => {
  const query = `
    WITH AggregatedResults AS (
      SELECT 
        Users.parent_email,
        Users.parent_phone,
        Users.full_name,
        COALESCE(
          GROUP_CONCAT(
            DISTINCT CONCAT(
              'Test: ', Tests.test_title, '\n',
              'Test Score: ', TestSubmissions.score, '/', 
              (SELECT COUNT(Questions.question_id) 
               FROM Questions 
               JOIN Passages ON Questions.passage_id = Passages.passage_id 
               WHERE Passages.test_id = Tests.test_id), '\n\n'
            ) SEPARATOR '\n\n'
          ), 
          ''
        ) AS test_results,
        COALESCE(
          GROUP_CONCAT(
            DISTINCT CONCAT(
              'Homework: ', Homeworks.homework_title, '\n',
              'Homework Score: ', HomeworkSubmissions.score, '/', 
              (SELECT COUNT(HomeworkQuestions.question_id) 
               FROM HomeworkQuestions 
               JOIN HomeworkPassages ON HomeworkQuestions.passage_id = HomeworkPassages.passage_id 
               WHERE HomeworkPassages.homework_id = Homeworks.homework_id), '\n\n'
            ) SEPARATOR '\n\n'
          ),
          ''
        ) AS homework_results,
        COALESCE(
          GROUP_CONCAT(
            DISTINCT CONCAT(
              'Attendance on ', AttendanceSessions.session_date, ': ', 
              AttendanceRecords.status, '\n\n'
            ) SEPARATOR '\n\n'
          ), 
          ''
        ) AS attendance_results
      FROM 
        Users
      LEFT JOIN 
        TestSubmissions ON Users.user_id = TestSubmissions.user_id
      LEFT JOIN 
        Tests ON TestSubmissions.test_id = Tests.test_id
      LEFT JOIN 
        HomeworkSubmissions ON Users.user_id = HomeworkSubmissions.user_id
      LEFT JOIN 
        Homeworks ON HomeworkSubmissions.homework_id = Homeworks.homework_id
      LEFT JOIN 
        AttendanceRecords ON Users.user_id = AttendanceRecords.user_id
      LEFT JOIN 
        AttendanceSessions ON AttendanceRecords.session_id = AttendanceSessions.session_id
      WHERE 
        Users.role != 'admin'
      GROUP BY 
        Users.parent_email, Users.parent_phone, Users.full_name
    )

    SELECT 
      parent_email,
      parent_phone,
      full_name,
      CONCAT(
        'Dear Parent,\n\nHere are the results for your child, ', full_name, ':\n\n',
        test_results,
        homework_results,
        attendance_results,
        'Best regards,\nYour School'
      ) AS results_message
    FROM 
      AggregatedResults;
  `;

  try {
    const results = await queryDatabase(query);

    if (results.length === 0) {
      return res.status(404).json({ error: "No users found." });
    }

    const numbersAndMessages = results.map(user => ({
      phone: user.parent_phone,
      message: user.results_message
    }));

    results.forEach(user => {
      const { parent_email, results_message } = user;

      const mailOptions = {
        from: "your-email@gmail.com",
        to: parent_email,
        subject: `Your Child's Results`,
        text: results_message,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(`Error sending email to ${parent_email}:`, error);
        } else {
          console.log(`Email sent to ${parent_email}: ${info.response}`);
        }
      });
    });

    try {
      await sendWhatsAppMessages(numbersAndMessages);
      console.log("WhatsApp messages sent to all parents.");
    } catch (error) {
      console.error("Error sending WhatsApp messages: ", error);
    }

    res.status(200).json({
      success: true,
      message: "Emails and WhatsApp messages are being sent to all parents except admins.",
    });
  } catch (error) {
    console.error("Error retrieving user data:", error);
    return res.status(500).json({ error: "An error occurred while retrieving user data." });
  }
});

app.get("/check-submission/:testId", async (req, res) => {
  const { testId } = req.params;
  const { userId } = req.query;

  try {
    const query = "SELECT score FROM TestSubmissions WHERE test_id = ? AND user_id = ?";
    const results = await queryDatabase(query, [testId, userId]);

    if (results.length > 0) {
      const submission = results[0];

      const totalQuery = `
        SELECT COUNT(*) AS total
        FROM Questions q
        JOIN Passages p ON q.passage_id = p.passage_id
        JOIN Tests t ON p.test_id = t.test_id
        WHERE t.test_id = ?`;

      const totalResults = await queryDatabase(totalQuery, [testId]);
      const total = totalResults[0].total;

      return res.json({
        submitted: true,
        score: submission.score,
        total: total,
      });
    } else {
      return res.json({ submitted: false });
    }
  } catch (error) {
    console.error("Error checking submission:", error);
    return res.status(500).json({ error: "An error occurred" });
  }
});

app.post("/signup", async (req, res) => {
  const { full_name, email, password, phone, parent_phone, parent_name, parent_email } = req.body;

  if (!full_name || !email || !password || !phone || !parent_phone || !parent_name || !parent_email) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: full_name,
    });

    await admin.auth().setCustomUserClaims(userRecord.uid, { role: "user" });

    const sql = `INSERT INTO Users (full_name, email, password, phone, parent_phone, parent_name, parent_email) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;
    await queryDatabase(sql, [
      full_name,
      email,
      password,
      phone,
      parent_phone,
      parent_name,
      parent_email,
    ]);

    res.status(200).json({
      message: "User registered successfully and data saved to MySQL and Firebase!"
    });
  } catch (error) {
    console.error("Error creating new user: ", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const idToken = authorizationHeader.split("Bearer ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userRecord = await admin.auth().getUser(decodedToken.uid);

    req.session.userId = userRecord.uid;
    req.session.userRole = decodedToken.role || "user";
    const fullName = userRecord.displayName || "User";

    if (req.session.userRole === "admin") {
      res.status(200).json({
        success: true,
        redirect: "/admin.html",
        message: "Admin login successful!",
      });
    } else {
      res.status(200).json({
        success: true,
        redirect: "/loggedIn.html",
        message: "User login successful!",
      });
    }
  } catch (error) {
    console.error("Error logging in: ", error);
    res.status(500).json({ error: "An error occurred while logging in." });
  }
});

app.get("/get-user-id", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const query = "SELECT user_id FROM Users WHERE email = ?";
    const results = await queryDatabase(query, [email]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ user_id: results[0].user_id });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/get-user", async (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).json({ error: "User ID not found" });
  }

  try {
    const query = "SELECT user_id, phone, parent_phone, full_name FROM Users WHERE user_Id = ?";
    const results = await queryDatabase(query, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(results[0]);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/user-test-grades/:userId', async (req, res) => {
  const userId = req.params.userId;

  const query = `
      SELECT 
          t.test_title AS exam_title, 
          ts.score AS exam_grade, 
          (SELECT COUNT(q.question_id) FROM Questions q 
           JOIN Passages p ON q.passage_id = p.passage_id 
           WHERE p.test_id = t.test_id) AS total_questions
      FROM 
          TestSubmissions ts
      JOIN 
          Tests t ON ts.test_id = t.test_id
      WHERE 
          ts.user_id = ?`;

  try {
    const results = await queryDatabase(query, [userId]);
    res.json(results);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/user-homework-grades/:userId', async (req, res) => {
  const userId = req.params.userId;

  const query = `
      SELECT 
          h.homework_title AS homework_title, 
          FLOOR(hs.score) AS homework_grade, 
          (SELECT COUNT(hq.question_id) FROM HomeworkQuestions hq 
           JOIN HomeworkPassages hp ON hq.passage_id = hp.passage_id 
           WHERE hp.homework_id = h.homework_id) AS total_questions
      FROM 
          HomeworkSubmissions hs
      JOIN 
          Homeworks h ON hs.homework_id = h.homework_id
      WHERE 
          hs.user_id = ?`;

  try {
    const results = await queryDatabase(query, [userId]);
    res.json(results);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/grade-exam/:testID", async (req, res) => {
  const { testID } = req.params;
  const { responses, user_id } = req.body;

  try {
    const checkSubmissionQuery = `SELECT * FROM TestSubmissions WHERE test_id = ? AND user_id = ?`;
    const submissionResults = await queryDatabase(checkSubmissionQuery, [testID, user_id]);

    if (submissionResults.length > 0) {
      return res.status(400).json({ error: "You have already submitted this test." });
    }

    const query = `
          SELECT q.question_id, q.correct_option
          FROM Questions q
          JOIN Passages p ON q.passage_id = p.passage_id
          JOIN Tests t ON p.test_id = t.test_id
          WHERE t.test_id = ?`;

    const questionResults = await queryDatabase(query, [testID]);

    if (questionResults.length === 0) {
      return res.status(404).send({ error: "Test not found" });
    }

    let score = 0;
    const total = questionResults.length;

    questionResults.forEach((question) => {
      const userResponse = responses.find(
        (response) => response.question_id == question.question_id
      );
      if (userResponse && userResponse.response === question.correct_option) {
        score++;
      }
    });

    const insertSubmissionQuery = `INSERT INTO TestSubmissions (test_id, user_id, score) VALUES (?, ?, ?)`;
    await queryDatabase(insertSubmissionQuery, [testID, user_id, score]);

    res.status(200).json({ score, total });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/add-exam", upload.none(), async (req, res) => {
  const {
    courseID,
    testTitle,
    passageContent,
    questionText,
    optionA,
    optionB,
    optionC,
    optionD,
    correctOption,
  } = req.body;

  if (!courseID || !testTitle) {
    return res.status(400).json({ error: "Course ID and test title are required." });
  }

  if (!Array.isArray(passageContent) || passageContent.length === 0) {
    return res.status(400).json({ error: "No valid passages provided." });
  }

  if (!Array.isArray(questionText) || questionText.length === 0) {
    return res.status(400).json({ error: "No valid questions provided." });
  }

  try {
    const query1 = "INSERT INTO Tests (course_id, test_title) VALUES (?, ?)";
    const result1 = await queryDatabase(query1, [courseID, testTitle]);
    const testID = result1.insertId;

    let passages = [];
    for (let i = 0; i < passageContent.length; i++) {
      passages.push([testID, "text", passageContent[i]]);
    }

    const query2 = "INSERT INTO Passages (test_id, passage_type, content) VALUES ?";
    const result2 = await queryDatabase(query2, [passages]);
    const passageID = result2.insertId;

    let allQuestions = [];
    for (let i = 0; i < questionText.length; i++) {
      if (
        questionText[i] &&
        optionA[i] &&
        optionB[i] &&
        optionC[i] &&
        optionD[i] &&
        correctOption[i]
      ) {
        allQuestions.push([
          passageID + Math.floor(i / (questionText.length / passageContent.length)), // Adjust passageID increment based on distribution
          questionText[i],
          optionA[i],
          optionB[i],
          optionC[i],
          optionD[i],
          correctOption[i],
        ]);
      } else {
        console.error(`Invalid data for question ${i}`);
      }
    }

    if (allQuestions.length === 0) {
      return res.status(400).json({ error: "No valid questions provided." });
    }

    const query3 = "INSERT INTO Questions (passage_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES ?";
    await queryDatabase(query3, [allQuestions]);

    res.status(200).json({ message: "Exam added successfully", testID: testID });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/get-exam/:testID", async (req, res) => {
  const { testID } = req.params;
  const query = `
      SELECT t.test_title, p.passage_id, p.passage_type, p.content, q.question_id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
      FROM Tests t
      LEFT JOIN Passages p ON t.test_id = p.test_id
      LEFT JOIN Questions q ON p.passage_id = q.passage_id
      WHERE t.test_id = ?`;

  try {
    const results = await queryDatabase(query, [testID]);

    if (results.length === 0) {
      return res.status(404).send({ error: "Test not found" });
    }

    let exam = {
      test_title: results[0].test_title,
      passages: [],
    };

    let passagesMap = {};

    results.forEach((row) => {
      if (!passagesMap[row.passage_id]) {
        passagesMap[row.passage_id] = {
          passage_id: row.passage_id,
          passage_type: row.passage_type,
          content: row.content,
          questions: [],
        };
      }
      passagesMap[row.passage_id].questions.push({
        question_id: row.question_id,
        question_text: row.question_text,
        options: {
          a: row.option_a,
          b: row.option_b,
          c: row.option_c,
          d: row.option_d,
        },
        correct_option: row.correct_option,
      });
    });

    exam.passages = Object.values(passagesMap);

    res.status(200).json(exam);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/add-homework", upload.none(), async (req, res) => {
  const {
    courseID,
    homeworkTitle,
    passageContent,
    questionText,
    optionA,
    optionB,
    optionC,
    optionD,
    correctOption,
  } = req.body;

  if (!courseID || !homeworkTitle) {
    return res.status(400).json({ error: "Course ID and homework title are required." });
  }

  if (!Array.isArray(passageContent) || passageContent.length === 0) {
    return res.status(400).json({ error: "No valid passages provided." });
  }

  if (!Array.isArray(questionText) || questionText.length === 0) {
    return res.status(400).json({ error: "No valid questions provided." });
  }

  try {
    const query1 = "INSERT INTO Homeworks (course_id, homework_title) VALUES (?, ?)";
    const result1 = await queryDatabase(query1, [courseID, homeworkTitle]);
    const homeworkID = result1.insertId;

    let passages = [];
    for (let i = 0; i < passageContent.length; i++) {
      passages.push([homeworkID, "text", passageContent[i]]);
    }

    const query2 = "INSERT INTO HomeworkPassages (homework_id, passage_type, content) VALUES ?";
    const result2 = await queryDatabase(query2, [passages]);
    const passageID = result2.insertId;

    let allQuestions = [];
    for (let i = 0; i < questionText.length; i++) {
      if (
        questionText[i] &&
        optionA[i] &&
        optionB[i] &&
        optionC[i] &&
        optionD[i] &&
        correctOption[i]
      ) {
        allQuestions.push([
          passageID + Math.floor(i / (questionText.length / passageContent.length)),
          questionText[i],
          optionA[i],
          optionB[i],
          optionC[i],
          optionD[i],
          correctOption[i],
        ]);
      } else {
        console.error(`Invalid data for question ${i}`);
      }
    }

    if (allQuestions.length === 0) {
      return res.status(400).json({ error: "No valid questions provided." });
    }

    const query3 = "INSERT INTO HomeworkQuestions (passage_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES ?";
    await queryDatabase(query3, [allQuestions]);

    res.status(200).json({ message: "Homework added successfully", homeworkID: homeworkID });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/get-homework/:homeworkID", async (req, res) => {
  const { homeworkID } = req.params;
  const query = `
      SELECT h.homework_title, hp.passage_id, hp.passage_type, hp.content, hq.question_id, hq.question_text, hq.option_a, hq.option_b, hq.option_c, hq.option_d, hq.correct_option
      FROM Homeworks h
      LEFT JOIN HomeworkPassages hp ON h.homework_id = hp.homework_id
      LEFT JOIN HomeworkQuestions hq ON hp.passage_id = hq.passage_id
      WHERE h.homework_id = ?`;

  try {
    const results = await queryDatabase(query, [homeworkID]);

    if (results.length === 0) {
      return res.status(404).send({ error: "Homework not found" });
    }

    let homework = {
      homework_title: results[0].homework_title,
      passages: [],
    };

    let passagesMap = {};

    results.forEach((row) => {
      if (!passagesMap[row.passage_id]) {
        passagesMap[row.passage_id] = {
          passage_id: row.passage_id,
          passage_type: row.passage_type,
          content: row.content,
          questions: [],
        };
      }
      passagesMap[row.passage_id].questions.push({
        question_id: row.question_id,
        question_text: row.question_text,
        options: {
          a: row.option_a,
          b: row.option_b,
          c: row.option_c,
          d: row.option_d,
        },
        correct_option: row.correct_option,
      });
    });

    homework.passages = Object.values(passagesMap);

    res.status(200).json(homework);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/grade-homework/:homeworkID", async (req, res) => {
  const { homeworkID } = req.params;
  const { responses, user_id } = req.body;

  try {
    const checkSubmissionQuery = `SELECT * FROM HomeworkSubmissions WHERE homework_id = ? AND user_id = ?`;
    const submissionResults = await queryDatabase(checkSubmissionQuery, [homeworkID, user_id]);

    if (submissionResults.length > 0) {
      return res.status(400).json({ error: "You have already submitted this homework." });
    }

    const query = `
          SELECT hq.question_id, hq.correct_option
          FROM HomeworkQuestions hq
          JOIN HomeworkPassages hp ON hq.passage_id = hp.passage_id
          JOIN Homeworks h ON hp.homework_id = h.homework_id
          WHERE h.homework_id = ?`;

    const questionResults = await queryDatabase(query, [homeworkID]);

    if (questionResults.length === 0) {
      return res.status(404).send({ error: "Homework not found" });
    }

    let score = 0;
    const total = questionResults.length;

    questionResults.forEach((question) => {
      const userResponse = responses.find(
        (response) => response.question_id == question.question_id
      );
      if (userResponse && userResponse.response === question.correct_option) {
        score++;
      }
    });

    const insertSubmissionQuery = `INSERT INTO HomeworkSubmissions (homework_id, user_id, score) VALUES (?, ?, ?)`;
    await queryDatabase(insertSubmissionQuery, [homeworkID, user_id, score]);

    res.status(200).json({ score, total });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/check-homework-submission/:homeworkId', async (req, res) => {
  const { homeworkId } = req.params;
  const userId = req.query.userId;

  const totalQuestionsQuery = `
      SELECT COUNT(hq.question_id) AS total
      FROM HomeworkQuestions hq
      JOIN HomeworkPassages hp ON hq.passage_id = hp.passage_id
      WHERE hp.homework_id = ?`;

  const userScoreQuery = `
      SELECT score
      FROM HomeworkSubmissions
      WHERE homework_id = ? AND user_id = ?`;

  try {
    const totalResult = await queryDatabase(totalQuestionsQuery, [homeworkId]);
    const total = totalResult[0]?.total || 0;

    const scoreResult = await queryDatabase(userScoreQuery, [homeworkId, userId]);

    if (scoreResult.length === 0) {
      return res.status(404).send({ error: 'No submission found' });
    }

    const score = scoreResult[0]?.score || 0;
    res.json({ submitted: true, score, total });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/get-homework/:homeworkID", async (req, res) => {
  const { homeworkID } = req.params;
  const query = `
      SELECT h.homework_title, h.due_date, p.passage_id, p.passage_type, p.content, q.question_id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
      FROM Homeworks h
      LEFT JOIN HomeworkPassages p ON h.homework_id = p.homework_id
      LEFT JOIN HomeworkQuestions q ON p.passage_id = q.passage_id
      WHERE h.homework_id = ?`;

  try {
    const results = await queryDatabase(query, [homeworkID]);

    if (results.length === 0) {
      return res.status(404).send({ error: "Homework not found" });
    }

    let homework = {
      homework_title: results[0].homework_title,
      due_date: results[0].due_date,
      passages: [],
    };

    let passagesMap = {};

    results.forEach((row) => {
      if (!passagesMap[row.passage_id]) {
        passagesMap[row.passage_id] = {
          passage_id: row.passage_id,
          passage_type: row.passage_type,
          content: row.content,
          questions: [],
        };
      }
      passagesMap[row.passage_id].questions.push({
        question_id: row.question_id,
        question_text: row.question_text,
        options: {
          a: row.option_a,
          b: row.option_b,
          c: row.option_c,
          d: row.option_d,
        },
        correct_option: row.correct_option,
      });
    });

    homework.passages = Object.values(passagesMap);

    res.status(200).json(homework);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Could not log out, please try again" });
    }
    res.redirect("/");
  });
});

// User Routes
app.get("/loggedIn", isAuthenticated, (req, res) => {
  res.sendFile(path.join(publicDir, "loggedIn.html"));
});

app.get("/admin", isAuthenticated, (req, res) => {
  if (req.session.userRole === "admin") {
    res.sendFile(path.join(publicDir, "admin.html"));
  } else {
    res.status(403).send("Access denied");
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/check-session", (req, res) => {
  if (req.session.userId) {
    res.json({
      loggedIn: true,
      redirect: req.session.userRole === "admin" ? "/admin.html" : "/loggedIn.html",
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// Serve login.html directly
app.get("/login", (req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

app.post("/add-course", upload.single("courseImage"), async (req, res) => {
  const { courseName, courseLocation } = req.body;
  const courseImage = req.file ? req.file.filename : null;

  if (!courseName || !courseLocation) {
    return res.status(400).json({ error: "Course name and location are required." });
  }

  const query = "INSERT INTO Courses (course_name, location, image) VALUES (?, ?, ?)";
  try {
    const results = await queryDatabase(query, [courseName, courseLocation, courseImage]);
    res.status(200).json({ message: "Course added successfully!", id: results.insertId });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/get-Requests", async (req, res) => {
  const query = "SELECT * FROM Requests";

  try {
    const results = await queryDatabase(query);
    res.json(results);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/check-request", async (req, res) => {
  const { userId, courseId } = req.query;
  const query = "SELECT * FROM Requests WHERE user_id = ? AND course_id = ?";

  try {
    const results = await queryDatabase(query, [userId, courseId]);
    res.json({ submitted: results.length > 0 });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/accept-request", async (req, res) => {
  const { userId, email, course_id } = req.body;

  const enrollQuery = "INSERT INTO Enrollments (user_id, email, course_id) VALUES (?, ?, ?)";
  const deleteRequestQuery = "DELETE FROM Requests WHERE user_id = ? AND course_id = ?";

  try {
    await queryDatabase(enrollQuery, [userId, email, course_id]);
    await queryDatabase(deleteRequestQuery, [userId, course_id]);
    res.json({ message: "Request accepted and user enrolled successfully!" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/delete-request", async (req, res) => {
  const { userId, course_id } = req.body;
  const query = "DELETE FROM Requests WHERE user_id = ? AND course_id = ?";

  try {
    await queryDatabase(query, [userId, course_id]);
    res.json({ message: "Request deleted successfully!" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/join-course", async (req, res) => {
  const { courseId, userId, full_name, email } = req.body;

  if (!courseId || !userId || !full_name || !email) {
    return res.status(400).send({ success: false, error: "Missing required fields" });
  }

  const sql = "INSERT INTO Requests (full_name, email, course_id, user_id) VALUES (?, ?, ?, ?)";

  try {
    await queryDatabase(sql, [full_name, email, courseId, userId]);
    res.send({ success: true });
  } catch (error) {
    return res.status(500).send({ success: false, error: error.message });
  }
});

app.get("/get-Courses", async (req, res) => {
  const CoursesQuery = "SELECT * FROM Courses";

  try {
    const results = await queryDatabase(CoursesQuery);
    res.json(results);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/get-enrolled-users/:course_id", async (req, res) => {
  const { course_id } = req.params;
  const usersQuery = `
    SELECT Users.user_id, Users.full_name 
    FROM Enrollments 
    JOIN Users ON Enrollments.user_id = Users.user_id 
    WHERE Enrollments.course_id = ?;
  `;

  try {
    const results = await queryDatabase(usersQuery, [course_id]);
    res.json(results);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/attendance/sessions", async (req, res) => {
  const { course_id, session_date } = req.body;
  const createSessionQuery = "INSERT INTO AttendanceSessions (course_id, session_date) VALUES (?, ?)";

  try {
    const result = await queryDatabase(createSessionQuery, [course_id, session_date]);
    res.json({ session_id: result.insertId, course_id, session_date });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// Route to submit attendance records
app.post('/attendance/records', async (req, res) => {
  const { session_id, user_id, status } = req.body;
  const checkRecordQuery = 'SELECT * FROM AttendanceRecords WHERE session_id = ? AND user_id = ?';
  const createRecordQuery = 'INSERT INTO AttendanceRecords (session_id, user_id, status) VALUES (?, ?, ?)';

  try {
    const results = await queryDatabase(checkRecordQuery, [session_id, user_id]);

    if (results.length > 0) {
      return res.status(204).end();
    }

    const result = await queryDatabase(createRecordQuery, [session_id, user_id, status]);
    res.status(201).json({ record_id: result.insertId, session_id, user_id, status });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// Route to fetch all attendance sessions
app.get('/get-sessions/:course_id', async (req, res) => {
  const { course_id } = req.params;
  const sessionsQuery = `
    SELECT session_id, session_date
    FROM AttendanceSessions
    WHERE course_id = ?
    ORDER BY session_date DESC;
  `;

  try {
    const results = await queryDatabase(sessionsQuery, [course_id]);
    res.json(results);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/check-enrollment", async (req, res) => {
  const userId = req.query.userId;
  const courseId = req.query.courseId;

  if (!userId || !courseId) {
    return res.status(400).json({ error: "Missing userId or courseId" });
  }

  try {
    const enrollmentResults = await queryDatabase(
      "SELECT * FROM Enrollments WHERE user_id = ? AND course_id = ?",
      [userId, courseId]
    );

    res.json({ enrolled: enrollmentResults.length > 0 });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/Courses/:courseId", async (req, res) => {
  const courseId = req.params.courseId;

  const courseQuery = "SELECT * FROM Courses WHERE course_id = ?";
  const lecturesQuery = "SELECT * FROM Lectures WHERE course_id = ?";
  const homeworksQuery = "SELECT * FROM Homeworks WHERE course_id = ?";
  const testsQuery = "SELECT * FROM Tests WHERE course_id = ?";

  try {
    const courseResults = await queryDatabase(courseQuery, [courseId]);
    const lecturesResults = await queryDatabase(lecturesQuery, [courseId]);
    const homeworksResults = await queryDatabase(homeworksQuery, [courseId]);
    const testsResults = await queryDatabase(testsQuery, [courseId]);

    const courseData = {
      course: courseResults[0],
      lectures: lecturesResults,
      homeworks: homeworksResults,
      tests: testsResults,
    };

    res.json(courseData);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/add-lecture", upload.single("lectureFile"), async (req, res) => {
  const { courseID, lectureTitle } = req.body;
  const lectureFile = req.file ? req.file.filename : null;

  if (!courseID || !lectureTitle || !lectureFile) {
    return res.status(400).json({ error: "All fields are required." });
  }

  const query = "INSERT INTO Lectures (course_id, lecture_title, file_path) VALUES (?, ?, ?)";

  try {
    const results = await queryDatabase(query, [courseID, lectureTitle, lectureFile]);
    res.status(200).json({ message: "Lecture added successfully!", id: results.insertId });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/get-user-info", async (req, res) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const idToken = authorizationHeader.split("Bearer ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const email = decodedToken.email;

    const query = `SELECT email, full_name, role, user_id FROM Users WHERE email = ?`;
    const results = await queryDatabase(query, [email]);

    if (results.length > 0) {
      const user = results[0];
      res.json({
        success: true,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        user_id: user.user_id,
      });
    } else {
      res.status(404).json({ error: "User not found." });
    }
  } catch (error) {
    return res.status(500).json({ error: "An error occurred while verifying token." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
