const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const mysql2 = require("mysql2");
const admin = require("firebase-admin");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const nodemailer = require("nodemailer");
const twilio = require("twilio");
const dotenv = require('dotenv');


const puppeteer = require('puppeteer');

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

// Database connection
const db = mysql2.createConnection({
  host: "srv1458.hstgr.io",
  user: "u691495308_admin",
  password: "Admin@mayada1",  // replace with your actual password
  database: "u691495308_MayadaAcademy",
});

db.connect((err) => {
  if (err) {
    throw err;
  } else {
    console.log("Connected to database");
  }
});

// Firebase Admin SDK
const serviceAccount = require("./serviceAccountKey.json"); // replace with your service account key file

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware
async function isAuthenticated(req, res, next) {
  const idToken =
    req.headers.authorization && req.headers.authorization.split("Bearer ")[1];
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

  // Default path for most installations (may need customization)
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
    const formattedPhone = phone.replace(/^\+/, '');  // Remove the leading + if present
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
      await page.waitForTimeout(5000);  // Wait for 5 seconds before sending the next message
    } catch (error) {
      console.error(`Error sending message to ${formattedPhone}:`, error);
    }
  }

  await browser.close();
};

// Twilio client setup
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

  db.query(query, async (err, results) => {
    if (err) {
      console.error("Error retrieving user data:", err);
      return res.status(500).json({ error: "An error occurred while retrieving user data." });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "No users found." });
    }

    const numbersAndMessages = results.map(user => ({
      phone: user.parent_phone,
      message: user.results_message
    }));

    // Send email to each parent
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

    // Send WhatsApp messages using Puppeteer
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
  });
});



app.get("/check-submission/:testId", async (req, res) => {
  const { testId } = req.params;
  const { userId } = req.query;

  try {
    const query =
      "SELECT score FROM TestSubmissions WHERE test_id = ? AND user_id = ?";
    db.query(query, [testId, userId], (err, results) => {
      if (err) {
        console.error("Error checking submission:", err);
        return res.status(500).json({ error: "An error occurred" });
      }

      if (results.length > 0) {
        const submission = results[0];

        // Calculate total dynamically
        const totalQuery = `
          SELECT COUNT(*) AS total
          FROM Questions q
          JOIN Passages p ON q.passage_id = p.passage_id
          JOIN Tests t ON p.test_id = t.test_id
          WHERE t.test_id = ?`;

        db.query(totalQuery, [testId], (err, totalResults) => {
          if (err) {
            console.error("Error calculating total:", err);
            return res.status(500).json({ error: "An error occurred" });
          }

          const total = totalResults[0].total;

          return res.json({
            submitted: true,
            score: submission.score,
            total: total,
          });
        });
      } else {
        return res.json({ submitted: false });
      }
    });
  } catch (error) {
    console.error("Error checking submission:", error);
    return res.status(500).json({ error: "An error occurred" });
  }
});

app.post("/signup", async (req, res) => {
  const {
    full_name,
    email,
    password,
    phone,
    parent_phone,
    parent_name,
    parent_email,
  } = req.body;

  if (
    !full_name ||
    !email ||
    !password ||
    !phone ||
    !parent_phone ||
    !parent_name ||
    !parent_email
  ) {
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
    db.query(
      sql,
      [
        full_name,
        email,
        password,
        phone,
        parent_phone,
        parent_name,
        parent_email,
      ],
      (err, result) => {
        if (err) {
          console.error("Error inserting data: ", err);
          return res.status(500).json({ error: "An error occurred while registering." });
        } else {
          res.status(200).json({
            message: "User registered successfully and data saved to MySQL and Firebase!"
          });
        }
      }
    );
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

app.get("/get-user-id", (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const query = "SELECT user_id FROM Users WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ user_id: results[0].user_id });
  });
});


app.get("/get-user", (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).json({ error: "User ID not found" });
  }

  const query = "SELECT user_id, phone, parent_phone, full_name FROM Users WHERE user_Id = ?";
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(results[0]);
    console.log(results)

  });
});
app.get('/get-grades', (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).json({ error: 'User ID not found' });
  }

  const query = `
  SELECT 
    t.test_title, 
    ts.score AS test_grade, 
    h.homework_title, 
    hs.score AS homework_grade
  FROM Users u
  LEFT JOIN TestSubmissions ts ON u.user_id = ts.user_id
  LEFT JOIN Tests t ON ts.test_id = t.test_id
  LEFT JOIN HomeworkSubmissions hs ON u.user_id = hs.user_id
  LEFT JOIN Homeworks h ON hs.homework_id = h.homework_id
  WHERE u.user_id = ?
`;

  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      return res.status(404).json({ error: 'No grades found for the user' });
    }

    res.json(results);
  });
});

app.post("/grade-exam/:testID", (req, res) => {
  const { testID } = req.params;
  const { responses, user_id } = req.body;
  console.log(responses)

  // Check if the user has already submitted the test
  const checkSubmissionQuery = `SELECT * FROM TestSubmissions WHERE test_id = ? AND user_id = ?`;
  db.query(checkSubmissionQuery, [testID, user_id], (err, results) => {
    if (err) return res.status(500).send(err);

    if (results.length > 0) {
      return res
        .status(400)
        .json({ error: "You have already submitted this test." });
    }

    // Proceed with grading
    const query = `
          SELECT q.question_id, q.correct_option
          FROM Questions q
          JOIN Passages p ON q.passage_id = p.passage_id
          JOIN Tests t ON p.test_id = t.test_id
          WHERE t.test_id = ?`;

    db.query(query, [testID], (err, results) => {
      if (err) return res.status(500).send(err);

      if (results.length === 0) {
        return res.status(404).send({ error: "Test not found" });
      }

      let score = 0;
      const total = results.length;

      results.forEach((question) => {
        const userResponse = responses.find(
          (response) => response.question_id == question.question_id
        );
        if (userResponse && userResponse.response === question.correct_option) {
          score++;
        }
      });

      // Insert the submission record
      const insertSubmissionQuery = `INSERT INTO TestSubmissions (test_id, user_id, score) VALUES (?, ?, ?)`;
      db.query(
        insertSubmissionQuery,
        [testID, user_id, score],
        (err, results) => {
          if (err) return res.status(500).send(err);

          res.status(200).json({ score, total });
        }
      );
    });
  });
});

app.post("/add-exam", upload.none(), (req, res) => {
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

  console.log("Request body:", req.body); // Debugging output

  if (!courseID || !testTitle) {
    return res
      .status(400)
      .json({ error: "Course ID and test title are required." });
  }

  if (!Array.isArray(passageContent) || passageContent.length === 0) {
    return res.status(400).json({ error: "No valid passages provided." });
  }

  if (!Array.isArray(questionText) || questionText.length === 0) {
    return res.status(400).json({ error: "No valid questions provided." });
  }

  const query1 = "INSERT INTO Tests (course_id, test_title) VALUES (?, ?)";
  db.query(query1, [courseID, testTitle], (err, results) => {
    if (err) {
      console.error("Error inserting test:", err);
      return res.status(500).json({
        error: "An error occurred while adding the test.",
        details: err.message,
      });
    }
    const testID = results.insertId;

    let passages = [];
    for (let i = 0; i < passageContent.length; i++) {
      passages.push([testID, "text", passageContent[i]]);
    }

    const query2 =
      "INSERT INTO Passages (test_id, passage_type, content) VALUES ?";
    db.query(query2, [passages], (err, results) => {
      if (err) {
        console.error("Error inserting passages:", err);
        return res.status(500).json({
          error: "An error occurred while adding the passages.",
          details: err.message,
        });
      }

      const passageID = results.insertId; // Assuming this gives the first inserted ID

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
            passageID +
              Math.floor(i / (questionText.length / passageContent.length)), // Adjust passageID increment based on distribution
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

      const query3 =
        "INSERT INTO Questions (passage_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES ?";
      db.query(query3, [allQuestions], (err, results) => {
        if (err) {
          console.error("Error inserting questions:", err);
          return res.status(500).json({
            error: "An error occurred while adding the questions.",
            details: err.message,
          });
        }
        res
          .status(200)
          .json({ message: "Exam added successfully", testID: testID });
      });
    });
  });
});
// Route to get an exam
app.get("/get-exam/:testID", (req, res) => {
  const { testID } = req.params;
  const query = `
      SELECT t.test_title, p.passage_id, p.passage_type, p.content, q.question_id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
      FROM Tests t
      LEFT JOIN Passages p ON t.test_id = p.test_id
      LEFT JOIN Questions q ON p.passage_id = q.passage_id
      WHERE t.test_id = ?`;

  db.query(query, [testID], (err, results) => {
    if (err) return res.status(500).send(err);

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
  });
});

app.get("/get-exam/:testID", (req, res) => {
  const { testID } = req.params;
  const query = `
      SELECT t.test_title, p.passage_id, p.passage_type, p.content, q.question_id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
      FROM Tests t
      LEFT JOIN Passages p ON t.test_id = p.test_id
      LEFT JOIN Questions q ON p.passage_id = q.passage_id
      WHERE t.test_id = ?`;

  db.query(query, [testID], (err, results) => {
    if (err) return res.status(500).send(err);

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
  });
});



app.post("/add-homework", upload.none(), (req, res) => {
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
    return res
      .status(400)
      .json({ error: "Course ID and homework title are required." });
  }

  if (!Array.isArray(passageContent) || passageContent.length === 0) {
    return res.status(400).json({ error: "No valid passages provided." });
  }

  if (!Array.isArray(questionText) || questionText.length === 0) {
    return res.status(400).json({ error: "No valid questions provided." });
  }

  const query1 = "INSERT INTO Homeworks (course_id, homework_title) VALUES (?, ?)";
  db.query(query1, [courseID, homeworkTitle], (err, results) => {
    if (err) {
      console.error("Error inserting homework:", err);
      return res.status(500).json({
        error: "An error occurred while adding the homework.",
        details: err.message,
      });
    }
    const homeworkID = results.insertId;

    let passages = [];
    for (let i = 0; i < passageContent.length; i++) {
      passages.push([homeworkID, "text", passageContent[i]]);
    }

    const query2 =
      "INSERT INTO HomeworkPassages (homework_id, passage_type, content) VALUES ?";
    db.query(query2, [passages], (err, results) => {
      if (err) {
        console.error("Error inserting passages:", err);
        return res.status(500).json({
          error: "An error occurred while adding the passages.",
          details: err.message,
        });
      }

      const passageID = results.insertId;

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
            passageID +
              Math.floor(i / (questionText.length / passageContent.length)),
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

      const query3 =
        "INSERT INTO HomeworkQuestions (passage_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES ?";
      db.query(query3, [allQuestions], (err, results) => {
        if (err) {
          console.error("Error inserting questions:", err);
          return res.status(500).json({
            error: "An error occurred while adding the questions.",
            details: err.message,
          });
        }
        res
          .status(200)
          .json({ message: "Homework added successfully", homeworkID: homeworkID });
      });
    });
  });
});

app.get("/get-homework/:homeworkID", (req, res) => {
  const { homeworkID } = req.params;
  const query = `
      SELECT h.homework_title, hp.passage_id, hp.passage_type, hp.content, hq.question_id, hq.question_text, hq.option_a, hq.option_b, hq.option_c, hq.option_d, hq.correct_option
      FROM Homeworks h
      LEFT JOIN HomeworkPassages hp ON h.homework_id = hp.homework_id
      LEFT JOIN HomeworkQuestions hq ON hp.passage_id = hq.passage_id
      WHERE h.homework_id = ?`;

  db.query(query, [homeworkID], (err, results) => {
    if (err) return res.status(500).send(err);

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
  });
});



app.post("/grade-homework/:homeworkID", (req, res) => {
  const { homeworkID } = req.params;
  const { responses, user_id } = req.body;
  console.log('Received responses:', responses);


  const checkSubmissionQuery = `SELECT * FROM HomeworkSubmissions WHERE homework_id = ? AND user_id = ?`;
  db.query(checkSubmissionQuery, [homeworkID, user_id], (err, results) => {
    if (err) return res.status(500).send(err);

    if (results.length > 0) {
      return res
        .status(400)
        .json({ error: "You have already submitted this homework." });
    }

    const query = `
          SELECT hq.question_id, hq.correct_option
          FROM HomeworkQuestions hq
          JOIN HomeworkPassages hp ON hq.passage_id = hp.passage_id
          JOIN Homeworks h ON hp.homework_id = h.homework_id
          WHERE h.homework_id = ?`;

    db.query(query, [homeworkID], (err, results) => {
      if (err) return res.status(500).send(err);

      if (results.length === 0) {
        return res.status(404).send({ error: "Homework not found" });
      }

      let score = 0;
      const total = results.length;

      results.forEach((question) => {
        const userResponse = responses.find(
          (response) => response.question_id == question.question_id
        );
        if (userResponse && userResponse.response === question.correct_option) {
          score++;
        }
      });

      const insertSubmissionQuery = `INSERT INTO HomeworkSubmissions (homework_id, user_id, score) VALUES (?, ?, ?)`;
      db.query(
        insertSubmissionQuery,
        [homeworkID, user_id, score],
        (err, results) => {
          if (err) return res.status(500).send(err);

          res.status(200).json({ score, total });
        }
      );
    });
  });
});



// app.post("/add-homework", (req, res) => {
//   const { courseID, homeworkTitle, deadline, passages } = req.body;

//   console.log("Request body:", req.body); // Debugging output

//   if (!courseID || !homeworkTitle) {
//     return res
//       .status(400)
//       .json({ error: "Course ID and homework title are required." });
//   }

//   if (!Array.isArray(passages) || passages.length === 0) {
//     return res.status(400).json({ error: "No valid passages provided." });
//   }

//   const insertHomeworkQuery =
//     "INSERT INTO Homeworks (course_id, homework_title, due_date ) VALUES (?, ?, ?)";
//   db.query(
//     insertHomeworkQuery,
//     [courseID, homeworkTitle, deadline],
//     (err, results) => {
//       if (err) {
//         console.error("Error inserting homework:", err);
//         return res.status(500).json({
//           error: "An error occurred while adding the homework.",
//           details: err.message,
//         });
//       }

//       const homeworkID = results.insertId;
//       let passagesData = [];

//       for (let passage of passages) {
//         if (passage.content) {
//           passagesData.push([homeworkID, "text", passage.content]);
//         }
//       }

//       if (passagesData.length === 0) {
//         return res.status(400).json({ error: "No valid passages provided." });
//       }

//       const insertPassagesQuery =
//         "INSERT INTO HomeworkPassages (homework_id, passage_type, content) VALUES ?";
//       db.query(insertPassagesQuery, [passagesData], (err, results) => {
//         if (err) {
//           console.error("Error inserting passages:", err);
//           return res.status(500).json({
//             error: "An error occurred while adding the passages.",
//             details: err.message,
//           });
//         }

//         const firstPassageID = results.insertId; // Starting ID for passages

//         let allQuestions = [];
//         let questionCount = 0;
//         for (
//           let passageIndex = 0;
//           passageIndex < passages.length;
//           passageIndex++
//         ) {
//           const passage = passages[passageIndex];
//           const passageID = firstPassageID + passageIndex; // Increment passageID for each passage

//           for (let question of passage.questions) {
//             if (question.text && question.options && question.correctOption) {
//               allQuestions.push([
//                 passageID,
//                 question.text,
//                 question.options[0],
//                 question.options[1],
//                 question.options[2],
//                 question.options[3],
//                 question.correctOption,
//               ]);
//               questionCount++;
//             }
//           }
//         }

//         if (allQuestions.length === 0) {
//           return res
//             .status(400)
//             .json({ error: "No valid questions provided." });
//         }

//         const insertQuestionsQuery =
//           "INSERT INTO HomeworkQuestions (passage_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES ?";
//         db.query(
//           insertQuestionsQuery,
//           [allQuestions],
//           (err, questionResults) => {
//             if (err) {
//               console.error("Error inserting questions:", err);
//               return res.status(500).json({
//                 error: "An error occurred while adding the questions.",
//                 details: err.message,
//               });
//             }
//             res
//               .status(200)
//               .json({ message: "Homework added successfully", homeworkID });
//           }
//         );
//       });
//     }
//   );
// });

// app.post('/grade-homework/:homeworkID', (req, res) => {
//   const { homeworkID } = req.params;
//   const { responses, user_id } = req.body;

//   // Check if the user has already submitted the homework
//   const checkSubmissionQuery = `SELECT * FROM HomeworkSubmissions WHERE homework_id = ? AND user_id = ?`;
//   db.query(checkSubmissionQuery, [homeworkID, user_id], (err, results) => {
//     if (err) return res.status(500).send(err);

//     if (results.length > 0) {
//       return res.status(400).json({ error: 'You have already submitted this homework.' });
//     }

//     // Proceed with grading
//     const query = `
//       SELECT q.question_id, q.correct_option
//       FROM HomeworkQuestions q
//       JOIN HomeworkPassages p ON q.passage_id = p.passage_id
//       JOIN Homeworks h ON p.homework_id = h.homework_id
//       WHERE h.homework_id = ?`;

//     db.query(query, [homeworkID], (err, results) => {
//       if (err) return res.status(500).send(err);

//       if (results.length === 0) {
//         return res.status(404).send({ error: 'Homework not found' });
//       }

//       let score = 0;
//       const total = results.length;

//       results.forEach(question => {
//         const userResponse = responses.find(response => response.question_id == question.question_id);
//         if (userResponse && userResponse.response === question.correct_option) {
//           score++;
//         }
//       });

//       // Insert the submission record
//       const insertSubmissionQuery = `INSERT INTO HomeworkSubmissions (homework_id, user_id, score) VALUES (?, ?, ?)`;
//       db.query(insertSubmissionQuery, [homeworkID, user_id, score], (err, results) => {
//         if (err) return res.status(500).send(err);

//         res.status(200).json({ score, total });
//       });
//     });
//   });
// });

// app.post("/grade-homework/:homeworkId", (req, res) => {
//   const { homeworkId } = req.params;
//   const { responses, user_id } = req.body;

//   // Check if the user has already submitted the homework
//   const checkSubmissionQuery = `SELECT * FROM HomeworkSubmissions WHERE homework_id = ? AND user_id = ?`;
//   db.query(checkSubmissionQuery, [homeworkId, user_id], (err, results) => {
//     if (err) return res.status(500).send(err);

//     if (results.length > 0) {
//       return res
//         .status(400)
//         .json({ error: "You have already submitted this homework." });
//     }

//     // Proceed with grading
//     const query = `
//       SELECT q.question_id, q.correct_option
//       FROM HomeworkQuestions q
//       JOIN HomeworkPassages p ON q.passage_id = p.passage_id
//       JOIN Homeworks h ON p.homework_id = h.homework_id
//       WHERE h.homework_id = ?`;

//     db.query(query, [homeworkId], (err, questions) => {
//       if (err) return res.status(500).send(err);

//       if (questions.length === 0) {
//         return res.status(404).send({ error: "Homework not found" });
//       }

//       let score = 0;
//       const total = questions.length;

//       questions.forEach((question) => {
//         const userResponse = responses.find(
//           (response) => response.question_id == question.question_id
//         );
//         if (userResponse && userResponse.response === question.correct_option) {
//           score++;
//         }
//       });

//       // Insert the submission record
//       const insertSubmissionQuery = `INSERT INTO HomeworkSubmissions (homework_id, user_id, score) VALUES (?, ?, ?)`;
//       db.query(
//         insertSubmissionQuery,
//         [homeworkId, user_id, score],
//         (err, results) => {
//           if (err) return res.status(500).send(err);

//           res.status(200).json({ score, total });
//         }
//       );
//     });
//   });
// });

// app.get("/get-homework/:homeworkId", (req, res) => {
//   const { homeworkId } = req.params;
//   const query = `
//   SELECT h.homework_title, p.passage_id, p.passage_type, p.content, 
//          q.question_id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
//   FROM Homeworks h
//   LEFT JOIN HomeworkPassages p ON h.homework_id = p.homework_id
//   LEFT JOIN HomeworkQuestions q ON p.passage_id = q.passage_id
//   WHERE h.homework_id = ?`;

//   db.query(query, [homeworkId], (err, results) => {
//     if (err) return res.status(500).send(err);

//     if (results.length === 0) {
//       return res.status(404).send({ error: "Homework not found" });
//     }

//     let homework = {
//       homework_title: results[0].homework_title,
//       passages: [],
//     };

//     let passagesMap = {};

//     results.forEach((row) => {
//       if (!passagesMap[row.passage_id]) {
//         passagesMap[row.passage_id] = {
//           passage_id: row.passage_id,
//           passage_type: row.passage_type,
//           content: row.content,
//           questions: [],
//         };
//       }
//       passagesMap[row.passage_id].questions.push({
//         question_id: row.question_id,
//         question_text: row.question_text,
//         options: {
//           a: row.option_a,
//           b: row.option_b,
//           c: row.option_c,
//           d: row.option_d,
//         },
//         correct_option: row.correct_option,
//       });
//     });

//     homework.passages = Object.values(passagesMap);

//     res.status(200).json(homework);
//   });
// });

app.post("/grade-homework/:homeworkID", (req, res) => {
  const { homeworkID } = req.params;
  const { responses, user_id } = req.body;
  console.log(req.body)

  // Check if the user has already submitted the homework
  const checkSubmissionQuery = `SELECT * FROM HomeworkSubmissions WHERE homework_id = ? AND user_id = ?`;
  db.query(checkSubmissionQuery, [homeworkID, user_id], (err, results) => {
      if (err) return res.status(500).send(err);

      if (results.length > 0) {
          return res.status(400).json({ error: "You have already submitted this homework." });
      }

      // Fetch questions and correct answers
      const query = `
          SELECT q.question_id, q.correct_option
          FROM HomeworkQuestions q
          JOIN HomeworkPassages p ON q.passage_id = p.passage_id
          JOIN Homeworks h ON p.homework_id = h.homework_id
          WHERE h.homework_id = ?`;

      db.query(query, [homeworkID], (err, results) => {
          if (err) return res.status(500).send(err);

          if (results.length === 0) {
              return res.status(404).send({ error: "Homework not found" });
          }

          let score = 0;
          const total = results.length;
          const correctAnswers = {};

          results.forEach((question) => {
              const userResponse = responses.find(
                  (response) => response.question_id == question.question_id
              );
              if (userResponse && userResponse.response === question.correct_option) {
                  score++;
              }
              correctAnswers[question.question_id] = question.correct_option;
          });

          // Insert the submission record
          const insertSubmissionQuery = `INSERT INTO HomeworkSubmissions (homework_id, user_id, score) VALUES (?, ?, ?)`;
          db.query(
              insertSubmissionQuery,
              [homeworkID, user_id, score],
              (err, results) => {
                  if (err) return res.status(500).send(err);

                  res.status(200).json({ score, total, correctAnswers });
              }
          );
      });
  });
});


app.get('/check-homework-submission/:homeworkId', (req, res) => {
  const { homeworkId } = req.params;
  const userId = req.query.userId;

  console.log(`Checking submission for homeworkId: ${homeworkId}, userId: ${userId}`);

  // Sample query to check submission status and retrieve score and total questions
  const totalQuestionsQuery = `
      SELECT COUNT(hq.question_id) AS total
      FROM HomeworkQuestions hq
      JOIN HomeworkPassages hp ON hq.passage_id = hp.passage_id
      WHERE hp.homework_id = ?`;

  const userScoreQuery = `
      SELECT score
      FROM HomeworkSubmissions
      WHERE homework_id = ? AND user_id = ?`;

  db.query(totalQuestionsQuery, [homeworkId], (err, totalResult) => {
      if (err) {
          console.error('Error fetching total questions:', err);
          return res.status(500).send(err);
      }

      const total = totalResult[0]?.total || 0;

      db.query(userScoreQuery, [homeworkId, userId], (err, scoreResult) => {
          if (err) {
              console.error('Error fetching user score:', err);
              return res.status(500).send(err);
          }

          if (scoreResult.length === 0) {
              console.warn('No submission found for user:', userId);
              return res.status(404).send({ error: 'No submission found' });
          }

          const score = scoreResult[0]?.score || 0;
          res.json({ submitted: true, score, total });
      });
  });
});


app.post("/add-homework", upload.none(), (req, res) => {
  const {
      courseID,
      homeworkTitle,
      dueDate,
      passageContent,
      questionText,
      optionA,
      optionB,
      optionC,
      optionD,
      correctOption,
  } = req.body;

  if (!courseID || !homeworkTitle || !dueDate) {
      return res.status(400).json({ error: "Course ID, title, and due date are required." });
  }

  // Insert into Homeworks table
  const query1 = "INSERT INTO Homeworks (course_id, homework_title, due_date) VALUES (?, ?, ?)";
  db.query(query1, [courseID, homeworkTitle, dueDate], (err, results) => {
      if (err) {
          console.error("Error inserting homework:", err);
          return res.status(500).json({
              error: "An error occurred while adding the homework.",
              details: err.message,
          });
      }
      const homeworkID = results.insertId;

      let passages = [];
      for (let i = 0; i < passageContent.length; i++) {
          passages.push([homeworkID, "text", passageContent[i]]);
      }

      const query2 = "INSERT INTO HomeworkPassages (homework_id, passage_type, content) VALUES ?";
      db.query(query2, [passages], (err, results) => {
          if (err) {
              console.error("Error inserting passages:", err);
              return res.status(500).json({
                  error: "An error occurred while adding the passages.",
                  details: err.message,
              });
          }

          const passageID = results.insertId; 

          let allQuestions = [];
          for (let i = 0; i < questionText.length; i++) {
              allQuestions.push([
                  passageID +
                    Math.floor(i / (questionText.length / passageContent.length)),
                  questionText[i],
                  optionA[i],
                  optionB[i],
                  optionC[i],
                  optionD[i],
                  correctOption[i],
              ]);
          }

          if (allQuestions.length === 0) {
              return res.status(400).json({ error: "No valid questions provided." });
          }

          const query3 =
              "INSERT INTO HomeworkQuestions (passage_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES ?";
          db.query(query3, [allQuestions], (err, results) => {
              if (err) {
                  console.error("Error inserting questions:", err);
                  return res.status(500).json({
                      error: "An error occurred while adding the questions.",
                      details: err.message,
                  });
              }
              res
                  .status(200)
                  .json({ message: "Homework added successfully", homeworkID: homeworkID });
          });
      });
  });
});

app.get("/get-homework/:homeworkID", (req, res) => {
  const { homeworkID } = req.params;
  const query = `
      SELECT h.homework_title, h.due_date, p.passage_id, p.passage_type, p.content, q.question_id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
      FROM Homeworks h
      LEFT JOIN HomeworkPassages p ON h.homework_id = p.homework_id
      LEFT JOIN HomeworkQuestions q ON p.passage_id = q.passage_id
      WHERE h.homework_id = ?`;

  db.query(query, [homeworkID], (err, results) => {
      if (err) return res.status(500).send(err);

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
  });
});







app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Could not log out, please try again" });
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
      redirect:
        req.session.userRole === "admin" ? "/admin.html" : "/loggedIn.html",
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// Serve login.html directly
app.get("/login", (req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

// Routes for courses and other functionalities
app.post("/add-course", upload.single("courseImage"), (req, res) => {
  const { courseName, courseLocation } = req.body;
  const courseImage = req.file ? req.file.filename : null;

  if (!courseName || !courseLocation) {
    return res
      .status(400)
      .json({ error: "Course name and location are required." });
  }

  const query =
    "INSERT INTO Courses (course_name, location, image) VALUES (?, ?, ?)";
  db.query(query, [courseName, courseLocation, courseImage], (err, results) => {
    if (err) {
      console.error("Error adding course: ", err);
      return res.status(500).json({
        error: "An error occurred while adding the course.",
        details: err.message,
      });
    }
    res
      .status(200)
      .json({ message: "Course added successfully!", id: results.insertId });
  });
});

app.get("/get-requests", (req, res) => {
  const query = "SELECT * FROM requests";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching requests:", err);
      return res
        .status(500)
        .json({ error: "An error occurred while fetching requests." });
    }
    console.log("Fetched requests:", results); // Add this line

    res.json(results);
  });
});


app.get("/check-request", (req, res) => {
  const { userId, courseId } = req.query;
  const query = "SELECT * FROM requests WHERE user_id = ? AND course_id = ?";

  db.query(query, [userId, courseId], (err, results) => {
    if (err) {
      console.error("Error checking request:", err);
      return res.status(500).json({ error: "An error occurred while checking the request." });
    }

    if (results.length > 0) {
      // Request already submitted
      res.json({ submitted: true });
    } else {
      // No request found
      res.json({ submitted: false });
    }
  });
});




app.post("/accept-request", (req, res) => {
  const { userId, email, course_id } = req.body;

  // Query to insert both userId and email
  const enrollQuery =
    "INSERT INTO Enrollments (user_id, email, course_id) VALUES (?, ?, ?)";
  const deleteRequestQuery =
    "DELETE FROM requests WHERE user_id = ? AND course_id = ?";

  db.query(enrollQuery, [userId, email, course_id], (err, enrollResults) => {
    if (err) {
      console.error("Error enrolling user:", err);
      return res
        .status(500)
        .json({ error: "An error occurred while enrolling user." });
    }
    db.query(deleteRequestQuery, [userId, course_id], (err, deleteResults) => {
      if (err) {
        console.error("Error deleting request:", err);
        return res
          .status(500)
          .json({ error: "An error occurred while deleting request." });
      }
      res.json({ message: "Request accepted and user enrolled successfully!" });
    });
  });
});

app.post("/delete-request", (req, res) => {
  const { userId, course_id } = req.body;
  const query = "DELETE FROM requests WHERE user_id = ? AND course_id = ?";

  db.query(query, [userId, course_id], (err, results) => {
    if (err) {
      console.error("Error deleting request:", err);
      return res
        .status(500)
        .json({ error: "An error occurred while deleting request." });
    }
    res.json({ message: "Request deleted successfully!" });
  });
});

app.post("/join-course", (req, res) => {
  const { courseId, userId, full_name, email } = req.body;
  console.log("Received raw body:", req.body);

  console.log("Received join course request with the following details:");
  console.log("Full Name:", full_name);
  console.log("Email:", email);
  console.log("Course ID:", courseId);
  console.log("User ID:", userId);

  if (!courseId || !userId || !full_name || !email) {
    console.error("Missing required fields");
    return res
      .status(400)
      .send({ success: false, error: "Missing required fields" });
  }



  
  const sql =
    "INSERT INTO requests (full_name, email, course_id, user_id) VALUES (?, ?, ?, ?)";
  db.query(sql, [full_name, email, courseId, userId], (err, result) => {
    if (err) {
      console.error("Error inserting request:", err);
      return res.status(500).send({ success: false, error: err });
    }
    console.log("Request inserted successfully:", result);
    res.send({ success: true });
  });
});

app.get("/get-courses", (req, res) => {
  const coursesQuery = "SELECT * FROM Courses";
  db.query(coursesQuery, (err, results) => {
    if (err) {
      console.error("Error fetching courses:", err);
      return res
        .status(500)
        .json({ error: "An error occurred while fetching courses." });
    }
    res.json(results);
  });
});

app.get("/get-enrolled-users/:course_id", (req, res) => {
  const { course_id } = req.params;
  const usersQuery = `
    SELECT Users.user_id, Users.full_name 
    FROM Enrollments 
    JOIN Users ON Enrollments.user_id = Users.user_id 
    WHERE Enrollments.course_id = ?;
  `;

  db.query(usersQuery, [course_id], (err, results) => {
    if (err) {
      console.error("Error fetching enrolled users:", err);
      return res
        .status(500)
        .json({ error: "An error occurred while fetching enrolled users." });
    }
    res.json(results);
  });
});

app.post("/attendance/sessions", (req, res) => {
  const { course_id, session_date } = req.body;
  const createSessionQuery =
    "INSERT INTO AttendanceSessions (course_id, session_date) VALUES (?, ?)";
  db.query(createSessionQuery, [course_id, session_date], (err, result) => {
    if (err) {
      console.error("Error creating session:", err);
      return res
        .status(500)
        .json({ error: "An error occurred while creating the session." });
    }
    res.json({ session_id: result.insertId, course_id, session_date });
  });
});

// Route to submit attendance records
// Route to submit attendance records
app.post('/attendance/records', (req, res) => {
  const { session_id, user_id, status } = req.body;
  const checkRecordQuery = 'SELECT * FROM AttendanceRecords WHERE session_id = ? AND user_id = ?';
  const createRecordQuery = 'INSERT INTO AttendanceRecords (session_id, user_id, status) VALUES (?, ?, ?)';

  db.query(checkRecordQuery, [session_id, user_id], (err, results) => {
    if (err) {
      console.error('Error checking existing attendance record:', err);
      return res.status(500).json({ error: 'An error occurred while checking attendance record.' });
    }

    if (results.length > 0) {
      // Record already exists, skip inserting
      return res.status(204).end(); // No Content response
    }

    // Record does not exist, proceed with insertion
    db.query(createRecordQuery, [session_id, user_id, status], (err, result) => {
      if (err) {
        console.error('Error recording attendance:', err);
        return res.status(500).json({ error: 'An error occurred while recording attendance.' });
      }
      res.status(201).json({ record_id: result.insertId, session_id, user_id, status });
    });
  });
});


// Route to fetch all attendance sessions
app.get('/get-sessions/:course_id', (req, res) => {
  const { course_id } = req.params;
  const sessionsQuery = `
    SELECT session_id, session_date
    FROM AttendanceSessions
    WHERE course_id = ?
    ORDER BY session_date DESC;
  `;
  db.query(sessionsQuery, [course_id], (err, results) => {
    if (err) {
      console.error('Error fetching sessions:', err);
      return res.status(500).json({ error: 'An error occurred while fetching sessions.' });
    }
    res.json(results);
  });
});



app.get("/check-enrollment", (req, res) => {
  const userId = req.query.userId;
  const courseId = req.query.courseId;

  if (!userId || !courseId) {
    console.error("Missing userId or courseId in request");
    return res.status(400).json({ error: "Missing userId or courseId" });
  }

  db.query(
    "SELECT * FROM Enrollments WHERE user_id = ? AND course_id = ?",
    [userId, courseId],
    (enrollmentErr, enrollmentResults) => {
      if (enrollmentErr) {
        console.error("Database query error:", enrollmentErr);
        return res.status(500).json({ error: enrollmentErr });
      }

      if (enrollmentResults.length > 0) {
        res.json({ enrolled: true });
      } else {
        res.json({ enrolled: false });
      }
    }
  );
});

app.get("/courses/:courseId", (req, res) => {
  const courseId = req.params.courseId;

  const courseQuery = "SELECT * FROM Courses WHERE course_id = ?";
  const lecturesQuery = "SELECT * FROM Lectures WHERE course_id = ?";
  const homeworksQuery = "SELECT * FROM Homeworks WHERE course_id = ?";
  const testsQuery = "SELECT * FROM Tests WHERE course_id = ?";

  db.query(courseQuery, [courseId], (courseErr, courseResults) => {
    if (courseErr) {
      console.error("Error fetching course details:", courseErr);
      return res
        .status(500)
        .json({ error: "An error occurred while fetching course details." });
    }

    db.query(lecturesQuery, [courseId], (lecturesErr, lecturesResults) => {
      if (lecturesErr) {
        console.error("Error fetching lectures:", lecturesErr);
        return res
          .status(500)
          .json({ error: "An error occurred while fetching lectures." });
      }

      db.query(homeworksQuery, [courseId], (homeworksErr, homeworksResults) => {
        if (homeworksErr) {
          console.error("Error fetching homeworks:", homeworksErr);
          return res
            .status(500)
            .json({ error: "An error occurred while fetching homeworks." });
        }

        db.query(testsQuery, [courseId], (testsErr, testsResults) => {
          if (testsErr) {
            console.error("Error fetching tests:", testsErr);
            return res
              .status(500)
              .json({ error: "An error occurred while fetching tests." });
          }

          const courseData = {
            course: courseResults[0],
            lectures: lecturesResults,
            homeworks: homeworksResults,
            tests: testsResults,
          };

          res.json(courseData);
        });
      });
    });
  });
});
app.post("/add-lecture", upload.single("lectureFile"), (req, res) => {
  const { courseID, lectureTitle } = req.body;
  const lectureFile = req.file ? req.file.filename : null;

  if (!courseID || !lectureTitle || !lectureFile) {
    return res.status(400).json({ error: "All fields are required." });
  }

  const query =
    "INSERT INTO Lectures (course_id, lecture_title, file_path) VALUES (?, ?, ?)";
  db.query(query, [courseID, lectureTitle, lectureFile], (err, results) => {
    if (err) {
      console.error("Error adding lecture: ", err);
      return res
        .status(500)
        .json({ error: "An error occurred while adding the lecture." });
    }
    res
      .status(200)
      .json({ message: "Lecture added successfully!", id: results.insertId });
  });
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

    // Query the database for the user's information
    const query = `SELECT email, full_name, role, user_id FROM Users WHERE email = ?`;
    db.query(query, [email], (err, results) => {
      if (err) {
        console.error("Error fetching user data:", err);
        return res
          .status(500)
          .json({ error: "An error occurred while retrieving user data." });
      }
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
    });
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(500).json({ error: "An error occurred while verifying token." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
