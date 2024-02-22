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
// Insert Employee Attendence
app.post('/insertEmployeeAttendence',verifyToken, async (req, res) => {
    const {
      iId, bShift1, bShift2, bShift3, bShift4, iCreateBy
    } = req.body;
  
    // if (!iId || !bShift1 || !bShift2 || !bShift3 || !bShift4 || !iCreateBy) {
    //   return res.status(400).json({ error: 'Please provide valid parameters.' });
    // }
  
    try {
      const request = new sql.Request();
  
      request.input('iId', sql.Int, iId);
      request.input('bShift1', sql.Bit, bShift1);
      request.input('bShift2', sql.Bit, bShift2);
      request.input('bShift3', sql.Bit, bShift3);
      request.input('bShift4', sql.Bit, bShift4);
      request.input('iCreateBy', sql.Int, iCreateBy);
      iCreateBy
  
      const query = `INSERT INTO [ERP].[dbo].[tblEmployeeAttendence]
        ([iId], [dtCreateDate], [bShift1], [bShift2], [bShift3], [bShift4],[iCreateBy])
        VALUES
        (@iId, GETDATE(), @bShift1, @bShift2, @bShift3, @bShift4, @iCreateBy)`;
  
      const result = await request.query(query);
  
      res.json({ message: "Updated Successfully" });
    } catch (err) {
      console.error('Error executing SQL query:', err);
      res.status(500).json({ error: 'Error executing SQL query.' });
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
app.get('/protectedRoute', verifyToken, (req, res) => {
  res.json({ status:true, message: 'You have access to this protected route.', userCode: req.userCode, userId: req.userId });
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

    const query = `USE ERPuserdb;
    INSERT INTO tblUserM
      ([sUserCode], [sPassword], [sFirstName], [sLastName], [sAddressLine1], [sAddressLine2], [sCity], [sState], [sPinCode], [sPhone1], [sEmail], [dtCreateDate], [dtJoinDate], [bStatus], [iCreatedBy])
      VALUES
      (@sUserCode, @sPassword, @sFirstName, @sLastName, @sAddressLine1, @sAddressLine2, @sCity, @sState, @sPinCode, @sPhone1, @sEmail, GETDATE() , @dtJoinDate, @bStatus, @iCreatedBy)`;

    const result = await request.query(query);

    res.json({ status: true, message: "User Added Successfully" });
  } catch (err) {
    // console.error('Error executing SQL query:', err);
    res.status(500).json({ status: false, message: "user Already Exists"});
  }
});

app.post('/assignGroupToMenus',verifyToken, async (req, res) => {
  const { bCheckState, iMenuId, iGroupId, iUserId } = req.body;

  try {
    const request = new sql.Request();

    request.input('bCheckState', sql.Bit, bCheckState);
    request.input('iMenuId', sql.Int, iMenuId);
    request.input('iGroupId', sql.Int, iGroupId);
    request.input('iUserId', sql.Int, iUserId);

    let query;

    if (bCheckState === 0) {
      query = `
        USE ERPuserdb;
        DELETE FROM tblGroupMenuM
        WHERE iGroupId = @iGroupId AND iMenuId = @iMenuId;
      `;
    } else {
      query = `
        USE ERPuserdb;
        DELETE FROM tblGroupMenuM
        WHERE iGroupId = @iGroupId AND iMenuId = @iMenuId;

        INSERT INTO tblGroupMenuM (iGroupId, iMenuId, bStatus, iCreatedBy)
        VALUES (@iGroupId, @iMenuId, 1, @iUserId);
      `;
    }

    await request.query(query);

    res.json({ message: 'Operation completed successfully' });
  } catch (err) {
    console.error('Error executing SQL query:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/assignGroupToUser',verifyToken, async (req, res) => {
  const { bCheckState, iUserId, iGroupId, iRoleUserId } = req.body;

  try {
    const request = new sql.Request();

    request.input('bCheckState', sql.Bit, bCheckState);
    request.input('iUserId', sql.Int, iUserId);
    request.input('iGroupId', sql.Int, iGroupId);
    request.input('iRoleUserId', sql.Int, iRoleUserId);

    let query;

    if (bCheckState === 0) {
      query = `
      USE ERPuserdb;
        DELETE FROM tblGroupUserM
        WHERE iUserId = @iRoleUserId AND iGroupId = @iGroupId;
      `;
    } else {
      query = `
      USE ERPuserdb;
        DELETE FROM tblGroupUserM
        WHERE iUserId = @iRoleUserId AND iGroupId = @iGroupId;

        INSERT INTO tblGroupUserM (iGroupId, iUserId, bStatus, iCreatedBy)
        VALUES (@iGroupId, @iRoleUserId, 1, @iUserId);
      `;
    }

    await request.query(query);

    res.json({ status: true, message: 'Operation completed successfully' });
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