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


  
// Checkin Employee Attendence

app.post('/checkin',verifyToken, async (req, res) => {
  const { iEmployeeId, iCreateBy } = req.body;

  try {
    const request = new sql.Request();

    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const isCheckinQuery = `
    USE ERP;
      DECLARE @employeeId INT = ${iEmployeeId};
      DECLARE @shiftCheckinStatus NVARCHAR(50);
      DECLARE @lastCheckinDate DATETIME;

      -- Check the status for the current shift
      SELECT TOP(1)
        CASE 
          WHEN bCheckStatus = 1 THEN 'CheckedOut'
          WHEN bCheckStatus = 0 THEN 'CheckedIn'
          ELSE 'NoRecord'
        END AS CheckinStatus,
        dtCreateDate AS LastCheckinDate
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
    const lastCheckinDate = resultCheckin.recordset[0]?.LastCheckinDate;

    // Check if last check-in date is the same as the current date
    const currentDate = new Date();
    if (
      checkinStatus === 'CheckedIn' &&
      lastCheckinDate &&
      new Date(lastCheckinDate).getDate() === currentDate.getDate() &&
      new Date(lastCheckinDate).getMonth() === currentDate.getMonth() &&
      new Date(lastCheckinDate).getFullYear() === currentDate.getFullYear()
    ) {
      return res.status(400).json({ status: false, message: "User Already CheckedIn for today's shift 1" });
    } else if (checkinStatus === 'CheckedOut') {
      return res.status(400).json({ status: false, message: "User Already CheckedOut for this shift" });
    }

    request.input('iCreateBy', sql.Int, iCreateBy);

    const insertQuery = `
    USE ERP;
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
app.post('/checkOut',verifyToken, async (req, res) => {
  const { iEmployeeId, iCreateBy } = req.body;

  try {
    const request = new sql.Request();

    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const checkinStatusQuery = `
    USE ERP;
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
    USE ERP;
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

app.get('/getAllEmployeeAttendance',verifyToken, async (req, res) => {
  try {
    const request = new sql.Request();
    const result = await request.query(`
    USE ERP;
    SELECT 
    ed.iEmployeeId AS employeeId,
    CONCAT(ed.sFirstName, ' ', ed.sLastName) AS FullName,
    ed.sEmploymentType AS EmploymentStatus,
    MAX(CASE WHEN ea.bCheckStatus = 0 THEN ea.dtCreateDate END) AS checkIn,
    MAX(CASE WHEN ea.bCheckStatus = 1 THEN ea.dtCreateDate END) AS checkOut
FROM 
    (
        SELECT iEmployeeId, sFirstName, sLastName, sEmploymentType FROM tblPermanentEmployeeData
        UNION ALL
        SELECT iEmployeeId, sFirstName, sLastName, sEmploymentType FROM tblInternData
    ) ed
LEFT JOIN 
    tblEmployeeAttendence ea ON ed.iEmployeeId = ea.iEmployeeId
GROUP BY 
    ed.iEmployeeId, CONCAT(ed.sFirstName, ' ', ed.sLastName), ed.sEmploymentType;

    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//checkin Status
app.get('/checkinStatus', async (req, res) => {
  const iEmployeeId = req.query.iEmployeeId;

  try {
    const request = new sql.Request();

    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const isCheckinQuery = `
    USE ERP;
    DECLARE @employeeId INT = @iEmployeeId;

    SELECT TOP(1)
      CASE 
        WHEN bCheckStatus = 1 THEN 'CheckedOut'
        WHEN bCheckStatus = 0 THEN 'CheckedIn'
        ELSE 'NoRecord'
      END AS cuurentStatus
    FROM tblEmployeeAttendence
    WHERE iEmployeeId = @employeeId
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

//get Permanent Employee
app.get('/getPermanentEmployee',verifyToken, async (req, res) => {
  const { iEmployeeId } = req.query; // Change this line to use req.query

  try {
    const request = new sql.Request();
    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const result = await request.query(`
      USE ERP;
      SELECT
        *
      FROM ERP.dbo.tblPermanentEmployeeData
      WHERE iEmployeeId = @iEmployeeId;
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


//get Intern Employee
app.get('/getInternEmployee',verifyToken, async (req, res) => {
  const { iEmployeeId } = req.query; // Change this line to use req.query

  try {
    const request = new sql.Request();
    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const result = await request.query(`
    USE ERP;
      SELECT
        *
      FROM ERP.dbo.tblInternData
      WHERE iEmployeeId = @iEmployeeId;
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getNullEmployees',verifyToken, async (req, res) => {
  try {
    const request = new sql.Request();
    const result = await request.query(`
    USE ERP;
    SELECT iEmployeeId, 
       sFirstName + ' ' + sLastName AS employeeName,
       sEmailId,
       sPhoneNumber,
       sEmploymentType,
	   dtCreateDate,
       bStatus
FROM tblPermanentEmployeeData
WHERE bStatus IS NULL

UNION

SELECT iEmployeeId, 
       sFirstName + ' ' + sLastName AS employeeName,
       sEmailId,
       sPhoneNumber,
       sEmploymentType,
	   dtCreateDate,
       bStatus
FROM tblInternData

UNION

SELECT iEmployeeId, 
       sFirstName + ' ' + sLastName AS employeeName,
       sEmailId,
       sPhoneNumber,
       sEmploymentType,
	   dtCreateDate,
       bStatus
FROM tblFreeLanceDetails

UNION

SELECT iEmployeeId, 
       sCompanyName AS employeeName,
       NULL AS sEmailId,
       sFounderContactNumber AS sPhoneNumber,
       sEmploymentType,
	   dtCreateDate,
       bStatus
FROM tblContractorDetails

UNION

SELECT iEmployeeId, 
       sCompanyName AS employeeName,
       sCompanyEmailId AS sEmailId,
       sCompanyContactNumber AS sPhoneNumber,
       sEmploymentType,
	   dtCreateDate,
       bStatus
FROM tblCoOperateData
WHERE bStatus IS NULL;
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//get Freelance
app.get('/getFreelanceDetails',verifyToken, async (req, res) => {
  const { iEmployeeId } = req.query; // Change this line to use req.query

  try {
    const request = new sql.Request();
    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const result = await request.query(`
    USE ERP;
      SELECT
        *
      FROM ERP.dbo.tblFreeLanceDetails
      WHERE iEmployeeId = @iEmployeeId;
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


//get Contractor
app.get('/getContractorDetails', verifyToken, async (req, res) => {
  const { iEmployeeId } = req.query; // Change this line to use req.query

  try {
    const request = new sql.Request();
    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const result = await request.query(`
    USE ERP;
      SELECT
        *
      FROM ERP.dbo.tblContractorDetails
      WHERE iEmployeeId = @iEmployeeId;
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// get CoOperate
app.get('/getCoOperate',verifyToken, async (req, res) => {
  const { iEmployeeId } = req.query; // Change this line to use req.query

  try {
    const request = new sql.Request();
    request.input('iEmployeeId', sql.Int, iEmployeeId);

    const result = await request.query(`
      SELECT
        *
      FROM ERP.dbo.tblCoOperateData
      WHERE iEmployeeId = @iEmployeeId;
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


//insert permanenet

app.post('/insertPermanentEmployeeData',verifyToken, async (req, res) => {
  const {
    sFirstName, sMiddleName, sLastName, dtDOB, sGender, sMaritalStatus, sAdd1, sAdd2,
    sCity, sState, sPinCode, sPhoneNumber, sEmailId, sAadhaarNumber, sPanNumber,
    dtEmploymentStartDate, dtEmployementEndDate, sJobTitle, sManagedBy, sDepartmentName, iCTC,sHighestQualification, sUniversityName, dtGraduationDate, iCreatedBy
  } = req.body;

  try {
    const request = new sql.Request();

    request.input('sFirstName', sql.NVarChar, sFirstName);
    request.input('sMiddleName', sql.NVarChar, sMiddleName);
    request.input('sLastName', sql.NVarChar, sLastName);
    request.input('dtDOB', sql.Date, dtDOB);
    request.input('sGender', sql.NVarChar, sGender);
    request.input('sMaritalStatus', sql.NVarChar, sMaritalStatus);
    request.input('sAdd1', sql.NVarChar, sAdd1);
    request.input('sAdd2', sql.NVarChar, sAdd2);
    request.input('sCity', sql.NVarChar, sCity);
    request.input('sState', sql.NVarChar, sState);
    request.input('sPinCode', sql.NVarChar, sPinCode);
    request.input('sPhoneNumber', sql.NVarChar, sPhoneNumber);
    request.input('sEmailId', sql.NVarChar, sEmailId);
    request.input('sAadhaarNumber', sql.NVarChar, sAadhaarNumber);
    request.input('sPanNumber', sql.NVarChar, sPanNumber);
    request.input('dtEmploymentStartDate', sql.DATE, dtEmploymentStartDate);
    request.input('dtEmployementEndDate', sql.DATE, dtEmployementEndDate);
    request.input('sJobTitle', sql.NVarChar, sJobTitle);
    request.input('sManagedBy', sql.NVarChar, sManagedBy);
    request.input('sDepartmentName', sql.NVarChar, sDepartmentName);
    // request.input('iEmploymentType', sql.INT, iEmploymentType);
    request.input('iCTC', sql.INT, iCTC);
    request.input('sHighestQualification', sql.VARCHAR, sHighestQualification);
    request.input('sUniversityName', sql.VARCHAR, sUniversityName);
    request.input('dtGraduationDate', sql.VARCHAR, dtGraduationDate);
    request.input('iCreatedBy', sql.INT, iCreatedBy);
   

    const query = `
    USE ERP;
      INSERT INTO [ERP].[dbo].[tblPermanentEmployeeData] 
      (
        [sFirstName], [sMiddleName], [sLastName],[dtDOB], [sGender], [sMaritalStatus], 
        [sAdd1], [sAdd2], [sCity], [sState], [sPinCode], [sPhoneNumber], [sEmailId], 
        [sAadhaarNumber], [sPanNumber], [dtEmploymentStartDate], [dtEmployementEndDate], 
        [sJobTitle], [sManagedBy], [sDepartmentName], [iCTC], [sHighestQualification],[sUniversityName],[dtGraduationDate],
        [iCreatedBy], [dtCreateDate], [sEmploymentType]
      )
      VALUES
      (
        @sFirstName, @sMiddleName, @sLastName, @dtDOB, @sGender, @sMaritalStatus, 
        @sAdd1, @sAdd2, @sCity, @sState, @sPinCode, @sPhoneNumber, @sEmailId, 
        @sAadhaarNumber, @sPanNumber, @dtEmploymentStartDate, @dtEmployementEndDate, 
        @sJobTitle, @sManagedBy, @sDepartmentName, @iCTC, @sHighestQualification, @sUniversityName, @dtGraduationDate,
        @iCreatedBy, GETDATE(), 'Permanent'
      )
    `;

    const result = await request.query(query);

    res.json({ message: "Inserted Successfully" });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});
// insert Intern Data
app.post('/insertInternData',verifyToken, async (req, res) => {
  const {
    sFirstName,
    sMiddleName,
    sLastName,
    dtDOB,
    sGender,
    sMaritalStatus,
    sAdd1,
    sAdd2,
    sCity,
    sState,
    sPinCode,
    sPhoneNumber,
    sEmailId,
    sAadhaarNumber,
    sPanNumber,
    sInternshipDetails,
    dtInternshipStartDate,
    dtInternshipEndDate,
    sInternTitle,
    sManagedBy,
    sDepartmentName,
    iCTC,
    sHighestQualification,
    sUniversityName,
    dtGraduationDate,
    iCreatedBy,
    dtCreateDate,
  } = req.body;

  try {
    const request = new sql.Request();

    request.input('sFirstName', sql.NVarChar, sFirstName);
    request.input('sMiddleName', sql.NVarChar, sMiddleName);
    request.input('sLastName', sql.NVarChar, sLastName);
    request.input('dtDOB', sql.NVarChar, dtDOB);
    request.input('sGender', sql.NVarChar, sGender);
    request.input('sMaritalStatus', sql.NVarChar, sMaritalStatus);
    request.input('sAdd1', sql.NVarChar, sAdd1);
    request.input('sAdd2', sql.NVarChar, sAdd2);
    request.input('sCity', sql.NVarChar, sCity);
    request.input('sState', sql.NVarChar, sState);
    request.input('sPinCode', sql.NVarChar, sPinCode);
    request.input('sPhoneNumber', sql.NVarChar, sPhoneNumber);
    request.input('sEmailId', sql.NVarChar, sEmailId);
    request.input('sAadhaarNumber', sql.NVarChar, sAadhaarNumber);
    request.input('sPanNumber', sql.NVarChar, sPanNumber);
    request.input('sInternshipDetails', sql.NVarChar, sInternshipDetails);
    request.input('dtInternshipStartDate', sql.Date, dtInternshipStartDate);
    request.input('dtInternshipEndDate', sql.Date, dtInternshipEndDate);
    request.input('sInternTitle', sql.NVarChar, sInternTitle);
    request.input('sManagedBy', sql.NVarChar, sManagedBy);
    request.input('sDepartmentName', sql.NVarChar, sDepartmentName);
    request.input('iCTC', sql.Int, iCTC);
    request.input('sHighestQualification', sql.VarChar, sHighestQualification);
    request.input('sUniversityName', sql.VarChar, sUniversityName);
    request.input('dtGraduationDate', sql.Date, dtGraduationDate);
    request.input('iCreatedBy', sql.Int, iCreatedBy);
    request.input('dtCreateDate', sql.DateTime, dtCreateDate);

    const query = `
    USE ERP;
      INSERT INTO [tblInternData]
      (
        [sFirstName],
        [sMiddleName],
        [sLastName],
        [dtDOB],
        [sGender],
        [sMaritalStatus],
        [sAdd1],
        [sAdd2],
        [sCity],
        [sState],
        [sPinCode],
        [sPhoneNumber],
        [sEmailId],
        [sAadhaarNumber],
        [sPanNumber],
        [sInternshipDetails],
        [dtInternshipStartDate],
        [dtInternshipEndDate],
        [sInternTitle],
        [sManagedBy],
        [sDepartmentName],
        [iCTC],
       [sHighestQualification],
        [sUniversityName],
        [dtGraduationDate],
        [iCreatedBy],
        [dtCreateDate],
        [sEmploymentType]
      )
      VALUES
      (
        @sFirstName,
        @sMiddleName,
        @sLastName,
        @dtDOB,
        @sGender,
        @sMaritalStatus,
        @sAdd1,
        @sAdd2,
        @sCity,
        @sState,
        @sPinCode,
        @sPhoneNumber,
        @sEmailId,
        @sAadhaarNumber,
        @sPanNumber,
        @sInternshipDetails,
        @dtInternshipStartDate,
        @dtInternshipEndDate,
        @sInternTitle,
        @sManagedBy,
        @sDepartmentName,
        @iCTC,
        @sHighestQualification,
        @sUniversityName,
        @dtGraduationDate,
        @iCreatedBy,
        @dtCreateDate,
        'Intern'
      )`;

    await request.query(query);

    res.json({ message: 'Inserted Successfully' });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});

// insertFreeLanceDetails

app.post('/insertFreeLanceDetails',verifyToken, async (req, res) => {
  const {
    sFirstName, sMiddleName, sLastName, sGender, sMaritalStatus, sAdd1, sAdd2, sCity, sState, sPinCode,
    sPhoneNumber, sEmailId, sAadhaarNumber, sPanNumber, dtContractStartDate, dtContractEndDate, sFreelanceTitle,
    sManagedBy, sDepartmentName, iContractAmt, iCreatedBy
  } = req.body;

  try {
    const request = new sql.Request();

    request.input('sFirstName', sql.NVarChar, sFirstName);
    request.input('sMiddleName', sql.NVarChar, sMiddleName);
    request.input('sLastName', sql.NVarChar, sLastName);
    request.input('sGender', sql.NVarChar, sGender);
    request.input('sMaritalStatus', sql.NVarChar, sMaritalStatus);
    request.input('sAdd1', sql.NVarChar, sAdd1);
    request.input('sAdd2', sql.NVarChar, sAdd2);
    request.input('sCity', sql.NVarChar, sCity);
    request.input('sState', sql.NVarChar, sState);
    request.input('sPinCode', sql.NVarChar, sPinCode);
    request.input('sPhoneNumber', sql.NVarChar, sPhoneNumber);
    request.input('sEmailId', sql.NVarChar, sEmailId);
    request.input('sAadhaarNumber', sql.NVarChar, sAadhaarNumber);
    request.input('sPanNumber', sql.NVarChar, sPanNumber);
    request.input('dtContractStartDate', sql.Date, dtContractStartDate);
    request.input('dtContractEndDate', sql.Date, dtContractEndDate);
    request.input('sFreelanceTitle', sql.NVarChar, sFreelanceTitle);
    request.input('sManagedBy', sql.NVarChar, sManagedBy);
    request.input('sDepartmentName', sql.NVarChar, sDepartmentName);
    request.input('iContractAmt', sql.Int, iContractAmt);
    request.input('iCreatedBy', sql.Int, iCreatedBy);

    const query = `
    USE ERP;
      INSERT INTO [tblFreeLanceDetails]
      (
        [sFirstName], [sMiddleName], [sLastName], [sGender], [sMaritalStatus], [sAdd1], [sAdd2], [sCity],
        [sState], [sPinCode], [sPhoneNumber], [sEmailId], [sAadhaarNumber], [sPanNumber], [dtContractStartDate],
        [dtContractEndDate], [sFreelanceTitle], [sManagedBy], [sDepartmentName], [iContractAmt], [iCreatedBy], [dtCreateDate], [sEmploymentType]
      )
      VALUES
      (
        @sFirstName, @sMiddleName, @sLastName, @sGender, @sMaritalStatus, @sAdd1, @sAdd2, @sCity, @sState, @sPinCode,
        @sPhoneNumber, @sEmailId, @sAadhaarNumber, @sPanNumber, @dtContractStartDate, @dtContractEndDate, @sFreelanceTitle,
        @sManagedBy, @sDepartmentName, @iContractAmt, @iCreatedBy, GETDATE(), 'Freelance'
      )`;

    const result = await request.query(query);

    res.json({ message: "Inserted Successfully" });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});

// insert cooperate
app.post('/insertCoOperateData',verifyToken, async (req, res) => {
  const {
    sCompanyName,
    sCompanyDepartment,
    sEmployeeName,
    sAdd1,
    sAdd2,
    sCity,
    sState,
    sPinCode,
    sCompanyContactNumber,
    sCompanyEmailId,
    sCompanyType,
    sGSTNumber,
    dtContractStartDate,
    dtContractEndDate,
    sContractSupervisor,
    iCreatedBy
  } = req.body;

  try {
    const request = new sql.Request();

    request.input('sCompanyName', sql.NVarChar(255), sCompanyName);
    request.input('sCompanyDepartment', sql.NVarChar(255), sCompanyDepartment);
    request.input('sEmployeeName', sql.NVarChar(255), sEmployeeName);
    request.input('sAdd1', sql.NVarChar(255), sAdd1);
    request.input('sAdd2', sql.NVarChar(255), sAdd2);
    request.input('sCity', sql.NVarChar(255), sCity);
    request.input('sState', sql.NVarChar(255), sState);
    request.input('sPinCode', sql.NVarChar(20), sPinCode);
    request.input('sCompanyContactNumber', sql.NVarChar(15), sCompanyContactNumber);
    request.input('sCompanyEmailId', sql.NVarChar(255), sCompanyEmailId);
    request.input('sCompanyType', sql.NVarChar(255), sCompanyType);
    request.input('sGSTNumber', sql.NVarChar(15), sGSTNumber);
    request.input('dtContractStartDate', sql.Date, dtContractStartDate);
    request.input('dtContractEndDate', sql.Date, dtContractEndDate);
    request.input('sContractSupervisor', sql.NVarChar(255), sContractSupervisor);
    request.input('iCreatedBy', sql.Int, iCreatedBy);

    const query = `USE ERP;
    INSERT INTO [tblCoOperateData]
      ([sCompanyName], [sCompanyDepartment], [sEmployeeName], [sAdd1], [sAdd2],
      [sCity], [sState], [sPinCode], [sCompanyContactNumber], [sCompanyEmailId], [sCompanyType],
      [sGSTNumber], [dtContractStartDate], [dtContractEndDate], [sContractSupervisor], [iCreatedBy], [dtCreateDate],[sEmploymentType])
      VALUES
      (@sCompanyName, @sCompanyDepartment, @sEmployeeName, @sAdd1, @sAdd2, @sCity,
      @sState, @sPinCode, @sCompanyContactNumber, @sCompanyEmailId, @sCompanyType, @sGSTNumber,
      @dtContractStartDate, @dtContractEndDate, @sContractSupervisor, @iCreatedBy, GETDATE(), 'CoOperate')`;

    const result = await request.query(query);

    res.json({ message: "Inserted Successfully" });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});


//insert contractor


app.post('/insertContractorDetails',verifyToken, async (req, res) => {
  const {
    sCompanyName, sFounderName, sFounderContactNumber, sCompanyContactNumber,
    sAdd1, sAdd2, sCity, sState, sPinCode, sGSTNumber, sSupervisorName,
    sSupervisorContactNumber, sWorkerName, sWorkerContactNumber, sAadhaarNumber,
    dtStartDate, dtEndDate, iContractPrice, sContractDetails, iCreateBy
  } = req.body;

  try {
    const request = new sql.Request();

    request.input('sCompanyName', sql.NVarChar, sCompanyName);
    request.input('sFounderName', sql.NVarChar, sFounderName);
    request.input('sFounderContactNumber', sql.NVarChar, sFounderContactNumber);
    request.input('sCompanyContactNumber', sql.NVarChar, sCompanyContactNumber);
    request.input('sAdd1', sql.NVarChar, sAdd1);
    request.input('sAdd2', sql.NVarChar, sAdd2);
    request.input('sCity', sql.NVarChar, sCity);
    request.input('sState', sql.NVarChar, sState);
    request.input('sPinCode', sql.NVarChar, sPinCode);
    request.input('sGSTNumber', sql.NVarChar, sGSTNumber);
    request.input('sSupervisorName', sql.NVarChar, sSupervisorName);
    request.input('sSupervisorContactNumber', sql.NVarChar, sSupervisorContactNumber);
    request.input('sWorkerName', sql.NVarChar, sWorkerName);
    request.input('sWorkerContactNumber', sql.NVarChar, sWorkerContactNumber);
    request.input('sAadhaarNumber', sql.NVarChar, sAadhaarNumber);
    request.input('dtStartDate', sql.DATE, dtStartDate);
    request.input('dtEndDate', sql.DATE, dtEndDate);
    request.input('iContractPrice', sql.INT, iContractPrice);
    request.input('sContractDetails', sql.NVarChar, sContractDetails);
    request.input('dtCreateDate', sql.DATETIME, new Date()); // Using GETDATE() to set the current date and time
    request.input('iCreateBy', sql.INT, iCreateBy);

    const query = `
    USE ERP;
      INSERT INTO [tblContractorDetails]
      (
        [sCompanyName], [sFounderName], [sFounderContactNumber], [sCompanyContactNumber],
        [sAdd1], [sAdd2], [sCity], [sState], [sPinCode], [sGSTNumber],
        [sSupervisorName], [sSupervisorContactNumber], [sWorkerName], [sWorkerContactNumber],
        [sAadhaarNumber], [dtStartDate], [dtEndDate], [iContractPrice], [sContractDetails],
        [dtCreateDate], [iCreateBy], [sEmploymentType]
      )
      VALUES
      (
        @sCompanyName, @sFounderName, @sFounderContactNumber, @sCompanyContactNumber,
        @sAdd1, @sAdd2, @sCity, @sState, @sPinCode, @sGSTNumber,
        @sSupervisorName, @sSupervisorContactNumber, @sWorkerName, @sWorkerContactNumber,
        @sAadhaarNumber, @dtStartDate, @dtEndDate, @iContractPrice, @sContractDetails,
        @dtCreateDate, @iCreateBy, 'Contractor'
      )
    `;

    const result = await request.query(query);

    res.json({ message: "Inserted Successfully" });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Error executing SQL query.' });
  }
});
// Approve Employee
app.put('/approveEmployee',verifyToken, async (req, res) => {
  const {
    iEmployeeId,
    sEmploymentType,
    iApprovedBy,
    bStatus
  } = req.body;

  try {
    // Use parameterized queries to prevent SQL injection
    const request = new sql.Request();
    request.input('iEmployeeId', sql.Int, iEmployeeId);
    request.input('sEmploymentType', sql.NVarChar(255), sEmploymentType);
    request.input('iApprovedBy', sql.Int, iApprovedBy);
    request.input('bStatus', sql.Bit, bStatus);

    // Use a switch statement for better readability
    let status;
    switch (sEmploymentType) {
      case 'Permanent':
        status = 'tblPermanentEmployeeData';
        break;
      case 'Freelance':
        status = 'tblFreeLanceDetails';
        break;
      case 'CoOperate':
        status = 'tblCoOperateData';
        break;
      case 'Intern':
        status = 'tblInternData';
        break;
      case 'Contractor':
        status = 'tblContractorDetails';
        break;
      default:
        return res.status(400).json({ error: 'Invalid Employment Type' });
    }

    // Use a template literal to include the table name dynamically
    const result = await request.query(`
  USE ERP; 
  UPDATE [${status}] 
  SET [bStatus] = @bStatus, [iApprovedBy] = @iApprovedBy, [dtApprovedDate] = GETDATE() 
  WHERE [iEmployeeId] = @iEmployeeId;
`);



    res.json({ message: 'Employee Approved successfully' });
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