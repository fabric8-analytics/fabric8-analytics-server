# CodeReady Analytics Core API Specifications

CodeReady Analytics is an open-source analytics platform aimed primarily at assisting developers in getting insights and recommendations on the selected dependency/package stack used for developing their applications.

This documentation is for developers who are interested in integrating their services or applications with CodeReady Analytics platform.

## **Supported ecosystems**

Below are the ecosystems that CodeReady Analytics currently supports.  We will be adding support for more ecosystems in the near future.
| | |
|-|-|
|**Ecosystem**|**Manifest file**|
| Java Maven | pom.xml |
| Python Pypi | requirements.txt |
| NodeJS | package.json |

## **Prerequisites**

Any new integration with the CodeReady Analytics platform will have to do that using an existing 3-scale API management gateway setup. Please reach out to us by raising an issue [here](https://github.com/fabric8-analytics/fabric8-analytics-vscode-extension/issues)

## **Initiate Dependency Analysis**

Submits a dependency stack analysis request

- **URL**
  `https://<3scale-api-gateway-url>/api/v1/stack-analyses`

- **Method**
  `POST`

- **Response Format**
  `jSON`

- **Path Parameters**
  `None`

- **Query Parameters**
  | | | | |
  |-|-|-|-|
  |**Name**|**Required**|**Description**|**Example**|
  | user_key | required | 3-scale API management authorization user key. | 421249d63 |

- **Form Data**
  | | | | |
  |-|-|-|-|
  |**Name**|**Required**|**Description**|**Example**|
  | manifest[] | required | Ecosystem specific Manifest file(s) available in the application. One can provide multiple manifest files to invoke the method. | @pom.xml |
  | filePath[] | required | Corresponding manifest file’s directory information. Care has to be taken to map the manifest filenames and file paths correctly. | /home/JohnDoe |

- **Headers**
  | | | | |
  |-|-|-|-|
  |**Name**|**Required**|**Description**|**Example**|
  | source | required | Source of the request. | "vscode" |
  | ecosystem | required | Ecosystem | maven/pypi/npm |

- **Sample Request with cURL**

  ``` 
  $ curl -k -F "manifest[]=@./pom.xml" -F "filePath[]=/home/JohnDoe" https://https://api-244552094075730.prod.gw.apicast.io:443/api/v1/stack-analyses/?user_key=421249d63
  ```

- **Sample Responses**

  **_Success_**

    ```
        {
        "id": "421249d9e1e5464cbf3e77dde4941463",
        "status": "success",
        "submitted_at": "2017-10-20 05:09:01.165068"
        }
    ```

  **_Failure_**
    ```
        400:
            {
                "error": "Bad request"
            }
    ```

    ```
        401:
            {
                "error": "Authentication failed - could not decode JWT token"
            }
    ```

## **Fetch Dependency Analysis**

Fetches dependency stack analysis response using the request identifier returned by initiate dependency analysis.

- **URL**
  `https://<3scale-api-gateway-url>/api/v1/stack-analyses/{request ID}`

- **Method**
  `GET`

- **Response Format**
  `jSON`

- **Path Parameters**
  | | | | |
  |-|-|-|-|
  |**Name**|**Required**|**Description**|**Example**|
  | {request ID} | required | Request identifier returned by /stack-analyses POST. | 421249d9e1e5464cbf3e77dde4941463 |

- **Query Parameters**
  | | | | |
  |-|-|-|-|
  |**Name**|**Required**|**Description**|**Example**|
  | user_key | required | 3-scale API management authorization user key. | 421249d63 |

- **Sample Request with cURL**

  ``` 
  $ curl -k https://https://api-244552094075730.prod.gw.apicast.io:443/api/v1/stack-analyses/421249d9e1e5464cbf3e77dde4941463 
  ```

- **Sample Responses**

  **_Success_**

    Sample success reponse is [here](https://gist.github.com/sivaavkd/1b27d01ccd17af839c0ba634ce9de628)

  **_In Progress_**
    ```
        202:
        {
            "error": "Analysis for request ID '510a314561104e8ba14bac489b31efe0' is in progress"
        }
    ```
  **_Failure_**
    ```
        400:
        {
            "error": "Bad request"
        }
    ```

## **Single Dependency Analysis**

Fetches various data points and recommendations for a given dependency.

- **URL**
  `https://<3scale-api-gateway-url>/api/v1/component-analyses/{ecosystem}/{name}/{version}`

- **Method**
  `GET`

- **Response Format**
  `jSON`

- **Data Parameters**
  `None`

- **Path Parameters**
  | | | | |
  |-|-|-|-|
  |**Name**|**Required**|**Description**|**Example**|
  | ecosystem | required | Ecosystem | maven/pypi/npm |
  | name | required | Name of the package | bootstrap/io.vertx:vertx-core |
  | version | required | version of the package | 3.4.1 |

- **Sample Request with cURL**

  ``` 
  $ curl -k https://api-244552094075730.prod.gw.apicast.io:443/api/v1/component-analyses/maven/io.vertx:vertx-core/3.4.1
  ```

- **Sample Responses**

  **_Success_**

    Sample success reponse is [here](https://gist.github.com/sivaavkd/6b4d27bcd60e57fcba6bc9d1546eb2d2)

  **_In Progress_**
    ```
        202:
        {
            "error": "Package npm/serve-static/1.7.x is unavailable. The package will be available shortly, please retry after some time."
        }
    ```
  **_Failure_**
    ```
        400:
        {
            "error": "Bad request"
        }
    ```
    ```
        401:
        {
            "error": "Authentication failed - could not decode JWT token"
        }
    ```
    ```
        404:
        {
            "error": "No data found for maven Package io.vertx:vertx-core/3.4.1"
        }
    ```
