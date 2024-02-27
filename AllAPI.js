const sql = require('mssql');
const express = require('express');
const dotenv = require('dotenv');
const http = require('http');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: true,
    trustServerCertificate: true,
  },
};

const apiKey = process.env.API_KEY;
const jwtSecret = process.env.JWT_SECRET;

async function connectToDatabase() {
  try {
    await sql.connect(dbConfig);
    console.log('Connected to the database');
  } catch (err) {
    console.error('Error connecting to the database:', err);
  }
}

function generateToken(userCode) {
  const payload = {
    userCode: userCode,
  };

  const options = {
    expiresIn: '30d', // Token expiration time
  };

  const token = jwt.sign(payload, jwtSecret, options);
  return token;
}

function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send('Unauthorized. Missing token.');
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).send('Unauthorized. Invalid token.');
    }

    req.userCode = decoded.userCode;
    next();
  });
}

function apiKeyMiddleware(req, res, next) {
  const requestApiKey = req.query.key;

  if (!requestApiKey || requestApiKey !== apiKey) {
    return res.status(401).send('Unauthorized. Invalid API key.');
  }

  next();
}

app.use(apiKeyMiddleware);
// Get employee Data
app.get('/getEmployeeData',verifyToken, async (req, res) => {
    const iId = req.query.iId;
  
    if (!iId) {
      return res.status(400).json({ error: 'Please provide valid parameters.' });
    }
  
    try {
      const request = new sql.Request();
  
      request.input('iId', sql.Int, iId);
  
      const query = `SELECT * FROM tblEmployeeData WHERE iId = @iId`;
  
      const result = await request.query(query);
  
      res.json(result.recordset);
    } catch (err) {
      console.error('Error executing SQL query:', err);
      res.status(500).json({ error: 'Error executing SQL query.' });
    }
  });

//Update Employee Data
app.put('/updateEmployeeData',verifyToken, async (req, res) => {
  const {
    iId, sFirstName, sMiddleName, sLastName, sGender, dtDob, sAdd1, sAdd2, sAdd3, sCity, sState,
    sPinCode, sAadhaarNumber, sPanCard, dtJoiningDate, sContactNumber, iCreatedBy,
    sGaurantor1, iEmployeeType
  } = req.body;

  if (!iId) {
    return res.status(400).json({ error: 'Please provide valid parameters.' });
  }

  try {
    const request = new sql.Request();

    // Build the dynamic SET clause based on provided parameters
    const setClause = Object.entries(req.body)
      .filter(([key, value]) => key !== 'iId' && value !== undefined)
      .map(([key]) => `[${key}] = @${key}`)
      .join(', ');

    const query = `
      UPDATE [ERP].[dbo].[tblEmployeeData]
      SET ${setClause}
      WHERE [iId] = @iId;
    `;

    // Log the query and parameters for debugging
    //console.log('SQL Query:', query);
    //console.log('Parameters:', req.body);

    // Set the parameters in the request
    Object.entries(req.body).forEach(([key, value]) => {
      if (key !== 'iId') {
        request.input(key, sql.VarChar, value);
      }
    });

    // Add the iId parameter separately
    request.input('iId', sql.Int, iId);

    const result = await request.query(query);

    res.json({ message: "Updated Successfully" });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});
// Insert Employee Data Update Log
app.post('/insertEmployeeUpdateLog',verifyToken, async (req, res) => {
    const {
      iId, iUpdatedBy
    } = req.body;
  
    if (!iId || !iUpdatedBy) {
      return res.status(400).json({ error: 'Please provide valid parameters.' });
    }
  
    try {
      const request = new sql.Request();
  
      request.input('iId', sql.Int, iId);
      request.input('iUpdatedBy', sql.Int, iUpdatedBy);
      
  
    const query = `INSERT INTO [ERP].[dbo].[tblEmployeeDataUpdateLog]
    ([iId], [sFirstName], [sMiddleName], [sLastName], [sGender], [dtDob], [sAdd1], [sAdd2], [sAdd3], [sCity], [sState],
    [sPinCode], [sAadhaarNumber], [sPanCard], [dtJoiningDate], [sContactNumber], [dtUpdateDate], [iUpdatedBy],
    [sGaurantor1], [iEmployeeType])
    SELECT
    [iId], [sFirstName], [sMiddleName], [sLastName], [sGender], [dtDob], [sAdd1], [sAdd2], [sAdd3], [sCity], [sState],
    [sPinCode], [sAadhaarNumber], [sPanCard], [dtJoiningDate], [sContactNumber], GETDATE(), @iUpdatedBy,
    [sGaurantor1], [iEmployeeType]
    FROM [ERP].[dbo].[tblEmployeeData]
    WHERE [iId] = @iId `;
  
      const result = await request.query(query);
  
      res.json({ message: "Updated Successfully" });
    } catch (err) {
      console.error('Error executing SQL query:', err);
      res.status(500).json({ error: 'Error executing SQL query.' });
    }
  });

// Insert Employee Data
app.post('/insertEmployeeData',verifyToken, async (req, res) => {
    const {
      sFirstName, sMiddleName, sLastName, sGender, dtDob, sAdd1, sAdd2, sAdd3, sCity, sState,
      sPinCode, sAadhaarNumber, sPanCard, dtJoiningDate, sContactNumber, iCreatedBy,
      sGaurantor1, iEmployeeType
    } = req.body;
  
    if (!sFirstName || !sLastName || !sGender || !dtDob || !sAdd1 || !sCity || !sState || !sPinCode || !sAadhaarNumber || !sPanCard || !sContactNumber || !iCreatedBy || !sGaurantor1 || !iEmployeeType) {
      return res.status(400).json({ error: 'Please provide valid parameters.' });
    }
  
    try {
      const request = new sql.Request();
  
      request.input('sFirstName', sql.VarChar, sFirstName);
      request.input('sMiddleName', sql.VarChar, sMiddleName);
      request.input('sLastName', sql.VarChar, sLastName);
      request.input('sGender', sql.Char, sGender);
      request.input('dtDob', sql.DateTime, dtDob);
      request.input('sAdd1', sql.VarChar, sAdd1);
      request.input('sAdd2', sql.VarChar, sAdd2);
      request.input('sAdd3', sql.VarChar, sAdd3);
      request.input('sCity', sql.VarChar, sCity);
      request.input('sState', sql.VarChar, sState);
      request.input('sPinCode', sql.VarChar, sPinCode);
      request.input('sAadhaarNumber', sql.VarChar, sAadhaarNumber);
      request.input('sPanCard', sql.VarChar, sPanCard);
      request.input('dtJoiningDate', sql.DateTime, dtJoiningDate);
      request.input('sContactNumber', sql.VarChar, sContactNumber);
      //request.input('dtCreateDate', sql.DateTime, dtCreateDate);
      request.input('iCreatedBy', sql.Int, iCreatedBy);
      request.input('sGaurantor1', sql.VarChar, sGaurantor1);
      request.input('iEmployeeType', sql.Int, iEmployeeType);
  
      const query = `INSERT INTO [ERP].[dbo].[tblEmployeeData]
        ([sFirstName], [sMiddleName], [sLastName], [sGender], [dtDob], [sAdd1], [sAdd2], [sAdd3], [sCity], [sState],
        [sPinCode], [sAadhaarNumber], [sPanCard], [dtJoiningDate], [sContactNumber], [dtCreateDate], [iCreatedBy],
        [sGaurantor1], [iEmployeeType])
        VALUES
        (@sFirstName, @sMiddleName, @sLastName, @sGender, @dtDob, @sAdd1, @sAdd2, @sAdd3, @sCity, @sState,
        @sPinCode, @sAadhaarNumber, @sPanCard, @dtJoiningDate, @sContactNumber, GETDATE(), @iCreatedBy,
        @sGaurantor1, @iEmployeeType)`;
  
      const result = await request.query(query);
  
      res.json({ message: "Updated Successfully" });
    } catch (err) {
      console.error('Error executing SQL query:', err);
      res.status(500).json({ error: 'Error executing SQL query.' });
    }
  });

// Checkin Employee Attendence

app.post('/checkin',verifyToken, async (req, res) => {
  const { iEmployeeId, iCreateBy } = req.body;

  try {
    const request = new sql.Request();

    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const isCheckinQuery = `
      DECLARE @employeeId INT = ${iEmployeeId};
      DECLARE @shiftCheckinStatus NVARCHAR(50);

      -- Check the status for the current shift
      SELECT TOP(1)
        CASE 
          WHEN bCheckStatus = 1 THEN 'CheckedOut'
          WHEN bCheckStatus = 0 THEN 'CheckedIn'
          ELSE 'NoRecord'
        END AS CheckinStatus
      FROM tblEmployeeAttendence
      WHERE iEmployeeId = @employeeId
        AND ((CONVERT(TIME, GETDATE()) BETWEEN '00:00:00' AND '04:00:00' AND bShift1 = 1)
            OR (CONVERT(TIME, GETDATE()) BETWEEN '10:00:00' AND '13:00:00' AND bShift2 = 1)
            OR (CONVERT(TIME, GETDATE()) BETWEEN '14:00:00' AND '18:00:00' AND bShift3 = 1)
            OR (CONVERT(TIME, GETDATE()) BETWEEN '19:00:00' AND '23:00:00' AND bShift4 = 1))
      ORDER BY dtCreateDate DESC;
    `;

    const resultCheckin = await request.query(isCheckinQuery);
    const checkinStatus = resultCheckin.recordset[0]?.CheckinStatus || 'NoRecord';

    if (checkinStatus === 'CheckedIn') {
      return res.status(400).json({ status: false, message: "User Already CheckedIn for this shift" });
    } else if (checkinStatus === 'CheckedOut') {
      return res.status(400).json({ status: false, message: "User Already CheckedOut for this shift" });
    }

    request.input('iCreateBy', sql.Int, iCreateBy);

    const insertQuery = `
      DECLARE @empId INT = ${iEmployeeId};
      DECLARE @createdById INT = ${iCreateBy};
      DECLARE @shift1 BIT;
      DECLARE @shift2 BIT;
      DECLARE @shift3 BIT;
      DECLARE @shift4 BIT;
      DECLARE @errorMessage NVARCHAR(100) = '';

      SET @shift1 = CASE
                        WHEN CONVERT(TIME, GETDATE()) BETWEEN '00:00:00' AND '04:00:00' THEN 1
                        ELSE 0
                     END;

      SET @shift2 = CASE
                        WHEN CONVERT(TIME, GETDATE()) BETWEEN '10:00:00' AND '13:00:00' THEN 1
                        ELSE 0
                     END;

      SET @shift3 = CASE
                        WHEN CONVERT(TIME, GETDATE()) BETWEEN '14:00:00' AND '18:00:00' THEN 1
                        ELSE 0
                     END;

      SET @shift4 = CASE
                        WHEN CONVERT(TIME, GETDATE()) BETWEEN '19:00:00' AND '23:00:00' THEN 1
                        ELSE 0
                     END;

      IF @shift1 = 0 AND @shift2 = 0 AND @shift3 = 0 AND @shift4 = 0
      BEGIN
          SET @errorMessage = 'Invalid Shift: Time is out of scope for all shifts.';
      END
      ELSE
      BEGIN
          INSERT INTO [ERP].[dbo].[tblEmployeeAttendence]
                ([iEmployeeId], [dtCreateDate], [bShift1], [bShift2], [bShift3], [bShift4], [iCreateBy], [bCheckStatus])
                VALUES
                (@empId, GETDATE(), @shift1, @shift2, @shift3, @shift4, @createdById, 0);
      END;

      SELECT @errorMessage AS ErrorMessage;  -- Include the error message in the result set
    `;

    const resultInsert = await request.query(insertQuery);
    const errorMessage = resultInsert.recordset[0]?.ErrorMessage || '';  // Retrieve the error message from the result set

    if (errorMessage) {
      return res.status(400).json({ status: false, message: errorMessage });
    } else {
      return res.json({ status: true, message: "Checked In Successfully" });
    }

  } catch (err) {
    console.error('Error executing SQL query:', err);
    return res.status(500).json({ error: 'Error executing SQL query.' });
  }
});

//checkout Employee Attendence
app.post('/checkOut', async (req, res) => {
  const { iEmployeeId, iCreateBy } = req.body;

  try {
    const request = new sql.Request();

    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const checkinStatusQuery = `
    DECLARE @employeeId INT = @iEmployeeId;

    SELECT TOP(1)
      CASE 
        WHEN bCheckStatus = 1 THEN 'CheckedOut'
        WHEN bCheckStatus = 0 THEN 'CheckedIn'
        ELSE 'NoRecord'
      END AS CheckinStatus
    FROM tblEmployeeAttendence
    WHERE iEmployeeId = @employeeId
    ORDER BY dtCreateDate DESC;`
    ;

    const checkinStatusResult = await request.query(checkinStatusQuery);
    const checkinStatus = checkinStatusResult.recordset[0]?.CheckinStatus || 'NoRecord';

    if (checkinStatus === 'CheckedOut') {
      return res.status(400).json({ status: false, message: "User Already CheckedOut for this shift" });
    } else if (checkinStatus === 'NoRecord') {
      return res.status(400).json({ status: false, message: "No attendance record found for the user" });
    }

    // If CheckedIn, proceed to insert the record with all shifts set to 0
    request.input('iCreateBy', sql.Int, iCreateBy);

    const insertQuery = `
      INSERT INTO [ERP].[dbo].[tblEmployeeAttendence]
      ([iEmployeeId], [dtCreateDate], [bShift1], [bShift2], [bShift3], [bShift4], [iCreateBy], [bCheckStatus])
      VALUES
      (@iEmployeeId, GETDATE(), 0, 0, 0, 0, @iCreateBy, 1);
    `;

    await request.query(insertQuery);

    return res.json({ status: true, message: "Checked Out Successfully" });

  } catch (err) {
    console.error('Error executing SQL query:', err);
    return res.status(500).json({ error: 'Error executing SQL query.' });
  }
});


//checkin Status
app.get('/checkinStatus', async (req, res) => {
  const iEmployeeId = req.query.iEmployeeId;

  try {
    const request = new sql.Request();

    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const isCheckinQuery = `
    DECLARE @iEmployeeId INT = @iEmployeeId;

    SELECT TOP(1)
      CASE 
        WHEN bCheckStatus = 1 THEN 'CheckedOut'
        WHEN bCheckStatus = 0 THEN 'CheckedIn'
        ELSE 'NoRecord'
      END AS cuurentStatus
    FROM tblEmployeeAttendence
    WHERE iEmployeeId = @iEmployeeId
    ORDER BY dtCreateDate DESC;`;

    const result = await request.query(isCheckinQuery);

    if (result.recordset.length === 0) {
      // No record found
      return res.json({ cuurentStatus: 'NULL' });
    }

    res.json(result.recordset[0]);

  } catch (err) {
    console.error('Error executing SQL query:', err);
    return res.status(500).json({ error: 'Error executing SQL query.' });
  }
});

  //Get All employee
  app.get('/getAllEmployeeData',verifyToken, async (req, res) => {
  


    try {
      const request = new sql.Request();
  
      const query = `SELECT iId, sFirstName, sLastName FROM tblEmployeeData`;
  
      const result = await request.query(query);
  
      res.json(result.recordset);
    } catch (err) {
      console.error('Error executing SQL query:', err);
      res.status(500).json({ error: 'Error executing SQL query.' });
    }
  });

  app.post('/loginAuth', async (req, res) => {
    const { sUserCode, sPassword } = req.body;
    console.log(sUserCode, sPassword)
    if (!sUserCode || !sPassword) {
      return res.status(400).json({ error: 'Please provide valid parameters.' });
    }
  
    try {
      await connectToDatabase(dbConfig);
      const request = new sql.Request();
  
      request.input('sUserCode', sql.VarChar, sUserCode);
  
      const query = `USE ERPuserdb;
                    SELECT * FROM tblUserM WHERE sUserCode = @sUserCode`;
      
      const result = await request.query(query);
      if (result.recordset.length > 0) {
        const hashedPassword = result.recordset[0].sPassword;
  
        if (sPassword === hashedPassword) {
          const userCode = result.recordset[0].sUserCode;
          const token = generateToken(userCode);
          res.json({ status: true, token });
        } else {
          res.json({ status: false, token: "" });
        }
      } else {
        res.json({ status: false, token: "" });
      }
    } catch (err) {
      console.error('Error executing SQL query:', err);
      res.status(500).json({ error: 'Error executing SQL query.' });
    }
  });

// Example protected route
app.get('/protectedRoute', verifyToken, async(req, res) => {
  const sUserCode = req.userCode;
  const request = new sql.Request();
  const query = `USE ERPuserdb;
         SELECT iId FROM tblUserM WHERE sUserCode = '${sUserCode}'`;
  const result = await request.query(query);
  const userId = ((result.recordset[0].iId));

  res.json({ status:true, message: 'You have access to this protected route.', userId: userId, userCode: req.userCode, });
});

app.put('/forgotPassword',verifyToken, async (req, res) => {
  const {
    sUserCode, iOTP, sPassword
  } = req.body;

  if (!sUserCode || !sPassword || !iOTP) {
    return res.status(400).json({ error: 'Please provide valid parameters.' });
  }

  try {
    const request = new sql.Request();

    request.input('sUserCode', sql.VarChar, sUserCode);
    request.input('sPassword', sql.VarChar, sPassword);
    request.input('iOTP', sql.Int, iOTP);

    if(iOTP === 12345){
        const query = `USE ERPuserdb; UPDATE tblUserM SET sPassword = @sPassword WHERE sUserCode = @sUserCode;`;
        const result = await request.query(query);
        res.json({ status: "Updated Successfully" });
    } else{
        res.json({ message: "Incorrect OTP" });
    };
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});

// ERPuserdb
app.post('/newUser', verifyToken, async (req, res) => {
  const {
    sUserCode, sPassword, sFirstName, sLastName, sAddressLine1, sAddressLine2, sCity, sState, sPinCode, sPhone1, sEmail, dtJoinDate, bStatus, iCreatedBy
  } = req.body;

  try {
    const request = new sql.Request();

    request.input('sUserCode', sql.VarChar, sUserCode);
    request.input('sPassword', sql.VarChar, sPassword);
    request.input('sFirstName', sql.VarChar, sFirstName);
    request.input('sLastName', sql.VarChar, sLastName);
    request.input('sAddressLine1', sql.VarChar, sAddressLine1);
    request.input('sAddressLine2', sql.VarChar, sAddressLine2);
    request.input('sCity', sql.VarChar, sCity);
    request.input('sState', sql.VarChar, sState);
    request.input('sPinCode', sql.VarChar, sPinCode);
    request.input('sPhone1', sql.VarChar, sPhone1);
    request.input('sEmail', sql.VarChar, sEmail);
    request.input('dtJoinDate', sql.Date, dtJoinDate);
    request.input('bStatus', sql.Bit, bStatus);
    request.input('iCreatedBy', sql.Int, iCreatedBy);

    const checkQuery = `USE ERPuserdb; SELECT CASE WHEN EXISTS (SELECT 1 FROM tbluserM WHERE sUserCode = '${sUserCode}') THEN 1 ELSE 0 END AS UserExists;`
    const result = await request.query(checkQuery);
      // res.json(result.recordset);
    const UserExists = Number(((result.recordset[0].UserExists)));
    
    if(UserExists === 1){
      res.status(500).json({ status: false, message: "user Already Exists"});
    }else if (UserExists === 0){
      const query = `USE ERPuserdb;
  INSERT INTO tblUserM
    ([sUserCode], [sPassword], [sFirstName], [sLastName], [sAddressLine1], [sAddressLine2], [sCity], [sState], [sPinCode], [sPhone1], [sEmail], [dtCreateDate], [dtJoinDate], [bStatus], [iCreatedBy])
    VALUES
    (@sUserCode, @sPassword, @sFirstName, @sLastName, @sAddressLine1, @sAddressLine2, @sCity, @sState, @sPinCode, @sPhone1, @sEmail, GETDATE() , @dtJoinDate, @bStatus, @iCreatedBy)`;

  const result = await request.query(query);

  res.json({ status: true, message: "User Added Successfully" });
    }
  
  } catch (err) {
      console.error('Error executing SQL query:', err);
    // res.status(500).json({ status: false, message: "user Already Exists"});
  }
});

app.post('/assignGroupToMenus', verifyToken, async (req, res) => {
  const { bCheckState, iMenuId, iGroupId, iUserId } = req.body;
  // console.log(bCheckState, iMenuId, iGroupId, iUserId)

  try {
    const request = new sql.Request();

    request.input('bCheckState', sql.Bit, bCheckState);
    request.input('iMenuId', sql.Int, iMenuId);
    request.input('iGroupId', sql.Int, iGroupId);
    request.input('iUserId', sql.Int, iUserId);

    let query;

    if (bCheckState == 0) {
      query = `USE ERPuserdb; DELETE FROM tblGroupMenuM WHERE iGroupId = @iGroupId AND iMenuId = @iMenuId;`;
    } else {
      query = `use ERPuserdb;
        BEGIN
          DELETE FROM tblGroupMenuM WHERE iGroupId = @iGroupId AND iMenuId = @iMenuId;

          INSERT INTO tblGroupMenuM (iGroupId, iMenuId, bStatus, iCreatedBy)
          VALUES (@iGroupId, @iMenuId, 1, @iUserId);
        END
      `;
    }

    await request.query(query);

    res.json({ message: 'Operation completed successfully' });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/assignGroupToUser', verifyToken, async (req, res) => {
  const { bCheckState, iUserId, iGroupId, iRoleUserId } = req.body;

  try {
    const transaction = new sql.Transaction();
    const request = new sql.Request(transaction);

    request.input('bCheckState', sql.Bit, bCheckState);
    request.input('iUserId', sql.Int, iUserId);
    request.input('iGroupId', sql.Int, iGroupId);
    request.input('iRoleUserId', sql.Int, iRoleUserId);

    await transaction.begin();

    try {
      let deleteQuery = `
        USE ERPuserdb;
        DELETE FROM tblGroupUserM
        WHERE iUserId = @iRoleUserId AND iGroupId = @iGroupId;
      `;

      await request.query(deleteQuery);

      if (bCheckState !== 0) {
        let insertQuery = `
        USE ERPuserdb;
          INSERT INTO tblGroupUserM (iGroupId, iUserId, bStatus, iCreatedBy)
          VALUES (@iGroupId, @iRoleUserId, 1, @iUserId);
        `;
        await request.query(insertQuery);
      }

      await transaction.commit();
      res.json({ status: true, message: 'Operation completed successfully' });
    } catch (error) {
      await transaction.rollback();
      console.error('Error executing SQL query:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  } catch (err) {
    console.error('Error starting transaction:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// ... (unchanged code for /getAssignedMenus)


app.get('/getAssignedMenus',verifyToken, async (req, res) => {
  const { iMenuId, iGroupId } = req.query;

  try {
    const request = new sql.Request();
    request.input('iMenuId', sql.Int, iMenuId);
    request.input('iGroupId', sql.Int, iGroupId);

    const query = `
    USE ERPuserdb;
      SELECT
        GM.iMenuId as GMId,
        CASE WHEN GM.iMenuId IS NULL THEN 'false' ELSE 'true' END as CheckState,
        M1.iId as iMenuId,
        M1.IParentMenuId,
        M1.sFormName,
        M1.sMenuName
      FROM
        tblMenuM M1
        LEFT JOIN tblGroupMenuM GM ON GM.iMenuId = M1.iId AND GM.iGroupId = @iGroupId
      WHERE
        M1.iParentMenuId = @iMenuId AND M1.bstatus = 1 AND M1.sFormName <> ''
      UNION
      SELECT
        GM.iMenuId as GMId,
        CASE WHEN GM.iMenuId IS NULL THEN 'false' ELSE 'true' END as CheckState,
        M2.iId as iMenuId,
        M2.IParentMenuId,
        M2.sFormName,
        M2.sMenuName
      FROM
        tblMenuM M1
        LEFT JOIN tblGroupMenuM GM ON GM.iMenuId = M1.iId AND GM.iGroupId = @iGroupId
        INNER JOIN tblMenuM M2 ON M2.iParentMenuId = M1.iId
      WHERE
        M1.iParentMenuId = @iMenuId AND M2.bstatus = 1 AND M2.sFormName <> ''
      ORDER BY
        M1.sMenuName;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.get('/getAssignedMenus',verifyToken, async (req, res) => {
  const { iMenuId, iGroupId } = req.query;

  try {
    const request = new sql.Request();
    request.input('iMenuId', sql.Int, iMenuId);
    request.input('iGroupId', sql.Int, iGroupId);

    const query = `
    USE ERPuserdb;
      SELECT
        GM.iMenuId as GMId,
        CASE WHEN GM.iMenuId IS NULL THEN 'false' ELSE 'true' END as CheckState,
        M1.iId as iMenuId,
        M1.IParentMenuId,
        M1.sFormName,
        M1.sMenuName
      FROM
        tblMenuM M1
        LEFT JOIN tblGroupMenuM GM ON GM.iMenuId = M1.iId AND GM.iGroupId = @iGroupId
      WHERE
        M1.iParentMenuId = @iMenuId AND M1.bstatus = 1 AND M1.sFormName <> ''
      UNION
      SELECT
        GM.iMenuId as GMId,
        CASE WHEN GM.iMenuId IS NULL THEN 'false' ELSE 'true' END as CheckState,
        M2.iId as iMenuId,
        M2.IParentMenuId,
        M2.sFormName,
        M2.sMenuName
      FROM
        tblMenuM M1
        LEFT JOIN tblGroupMenuM GM ON GM.iMenuId = M1.iId AND GM.iGroupId = @iGroupId
        INNER JOIN tblMenuM M2 ON M2.iParentMenuId = M1.iId
      WHERE
        M1.iParentMenuId = @iMenuId AND M2.bstatus = 1 AND M2.sFormName <> ''
      ORDER BY
        M1.sMenuName;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getMenuHeaders',verifyToken, async (req, res) => {
  try {
    const request = new sql.Request();
    const query =(`
    USE ERPuserdb;
    SELECT iId AS iMenuId, sMenuName, iParentMenuId, sFormName, bStatus, dtCreateDate, iDisplayOrder
    FROM ERPuserdb.dbo.tblMenuM
    WHERE iParentMenuId = 0
        AND bStatus = 1
    ORDER BY iDisplayOrder ASC;
    `);
    const result = await request.query(query);
    
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).send('Error executing SQL query.');
  }
});

app.get('/getMenu',verifyToken, async (req, res) => {
  const iUserId = req.query.iUserId;
  const iMenuId = req.query.iMenuId;

  try {
    const request = new sql.Request();

    request.input('iMenuId', sql.Int, iMenuId);
    request.input('iUserId', sql.Int, iUserId);

    const query =   `
    USE ERPuserdb;
    Select m.iId as iMenuId,m.sMenuName,m.iParentMenuId,m.sFormName,m.bStatus,m.dtCreateDate,m.iDisplayOrder 
    From tblMenuM m 
    inner Join tblGroupMenuM g on g.iMenuId =  m.iId 
    inner Join tblGroupUserM  u  on u.iGroupId  = g.iGroupId 
    where u.iUserId  = @iUserId  And m.bStatus =1  And g.bStatus = 1  And u.bStatus = 1 And m.iParentMenuId = @iMenuId 
     union 
     Select  m1.iId as iMenuId,m1.sMenuName,m1.iParentMenuId,m1.sFormName,m1.bStatus,m1.dtCreateDate,m1.iDisplayOrder From tblMenuM m1 
     inner Join(Select m.iId, m.iParentMenuId From tblMenuM m 
     inner Join tblGroupMenuM g on g.iMenuId =  m.iId 
     inner Join tblGroupUserM  u  on u.iGroupId  = g.iGroupId    where u.iUserId  = @iUserId  And m.bStatus =1  And g.bStatus = 1  And u.bStatus = 1  ) MC 
     On mc.iParentMenuId = m1.iId 
     where m1.iParentMenuId <> 0  And m1.iParentMenuId = @iMenuId order by 7`
     
    // const query = `USE [ERPuserdb]
    // DECLARE	@return_value int
    
    // EXEC	@return_value = [dbo].[uspGetMenuItems]
    //         @iMenuId = @iMenuId,
    //         @iUserId = @iUserId
    
    // SELECT	'Return Value' = @return_value
    // `;

    const result = await request.query(query);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});

app.get('/getRoles',verifyToken, async (req, res) => {
  try {
    const request = new sql.Request();

    const query = `
    USE ERPuserdb;
      SELECT
        [iId],
        [sGroupName],
        [sDescription],
        [bStatus],
        [dtCreateDate],
        [iCreatedBy]
      FROM
        tblGroupM
      WHERE
        bStatus = 1;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/getSubMenuItems',verifyToken, async (req, res) => {
  const { iMenuId, iUserId } = req.query;

  try {
    const request = new sql.Request();
    request.input('iMenuId', sql.Int, iMenuId);
    request.input('iUserId', sql.Int, iUserId);

    const query = `
    USE ERPuserdb;
      SELECT
        m.iID as iMenuId,
        m.sMenuName,
        m.iParentMenuId,
        m.sFormName,
        m.bStatus,
        m.dtCreateDate,
        m.iDisplayOrder
      FROM
        tblMenuM m
        INNER JOIN tblGroupMenuM g ON g.iMenuId = m.iID
        INNER JOIN tblGroupUserM u ON u.iGroupId = g.iGroupId
      WHERE
        u.iUserId = @iUserId AND
        m.bStatus = 1 AND
        g.bStatus = 1 AND
        u.bStatus = 1 AND
        m.iParentMenuId = @iMenuId
      ORDER BY
        m.iDisplayOrder ASC;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getUserLoginDetails',verifyToken, async (req, res) => {
  const { userId } = req.query;

  try {
    const request = new sql.Request();
    request.input('userId', sql.Int, userId);

    const query = `
        USE ERPuserdb;
      SELECT *
      FROM tblLoginL
      WHERE iUserId = @userId;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getUserRoles',verifyToken, async (req, res) => {
  const { iRoleUserId } = req.query;

  try {
    const request = new sql.Request();
    request.input('iRoleUserId', sql.Int, iRoleUserId);

    const query = `
    USE ERPuserdb;
      SELECT
        G1.iId as GId,
        G1.sGroupName,
        GU.iGroupId as 'GUid',
        CASE WHEN GU.iGroupId IS NULL THEN 0 ELSE 1 END as CheckState
      FROM
        tblGroupM G1
        LEFT JOIN (
          SELECT iGroupId
          FROM tblGroupUserM
          WHERE iUserId = @iRoleUserId
        ) AS GU ON GU.iGroupId = G1.iId
      WHERE
        G1.bStatus = 1;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getUsers',verifyToken, async (req, res) => {
  try {
    const request = new sql.Request();

    const query = `
    USE ERPuserdb;
      SELECT
        iId as iUserId,
        sUserCode,
        CONCAT(sFirstName, ' ', sLastName) as UserName
      FROM
        tblUserM
      WHERE
        bStatus = 1;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getUserName',verifyToken, async (req, res) => {
  const { iId } = req.query;

  try {
    const request = new sql.Request();
    request.input('iId', sql.Int, iId);

    const query = `
    USE ERPuserdb;
      SELECT
        iId as iUserId,
        sUserCode,
        CONCAT(sFirstName, ' ', sLastName) as UserName
      FROM
        tblUserM
      WHERE
        iId = @iId AND
        bStatus = 1;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/searchUserEmail',verifyToken, async (req, res) => {
  const { sUserCode } = req.query;

  try {
    const request = new sql.Request();
    request.input('sUserCode', sql.VarChar(15), sUserCode);

    const query = `
    USE ERPuserdb;
      SELECT
        iId,
        sPhone1,
        sEmail
      FROM
        tblUserM
      WHERE
        sUserCode = @sUserCode;
    `;

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/setPassword',verifyToken, async (req, res) => {
  const { sUserCode, sPassword } = req.body;

  try {
    const request = new sql.Request();
    request.input('sUserCode', sql.VarChar(35), sUserCode);
    request.input('sPassword', sql.VarChar(50), sPassword);

    const query = `
    USE ERPuserdb;
      UPDATE tblUserM
      SET sPassword = @sPassword, bStatus = 1
      WHERE sUserCode = @sUserCode;
    `;

    await request.query(query);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


const server = http.createServer(app);

server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
  connectToDatabase();
});


const gracefulShutdown = () => {
  server.close(() => {
    console.log('Server has been closed');
    sql.close().then(() => {
      console.log('Database connection pool has been closed');
      process.exit(0);
    });
  });
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);