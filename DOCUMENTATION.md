# WidevineFetch Module Documentation

<!-- TODO: Additional information API -->

### The following methods can be used to alter the data processing procedure of the program
+ Modify input
    + Modify the License URL, Headers and Body before they read the program
+ Get Challenge
    + A custom method for retrieving the Challenge from the body if advanced license wrapping techniques are being utilized
+ Set Challenge
    + A custom method for setting the Challenge in the body if advanced license wrapping techniques are being utilized

## Regex
Modules are activated by a RegEx that must **fully** match the License URL. \
Tools like [regex101](https://regex101.com//) can help you with creating your RegEx \
Multiple values can be specified
```python
REGEX = r"<License URL RegEx>"
# or
REGEX = [
    r"<License URL RegEx>",
    r"<License URL RegEx>"
]
```

## Force Impersonation
```python
IMPERSONATE = True
```
Useful when impersonation is required for a custom module

## Modify input
```python
def modify(
        url: str,
        headers: dict,
        body: str
) -> tuple[str, dict, str]:
    # <code>
    return url, headers, body

# Function reference
MODIFY = modify
```
> [!NOTE]  
> The body is received as a string and must be returned as a string


## Get Challenge
```python
def get_challenge(body: str) -> bytes | str:
    # <code>
    return "C..."

# Function reference
GET_CHALLENGE = get_challenge
```
> [!NOTE]  
> The body is received as a string. The Challenge can be returned as bytes or base64 (str)


## Set Challenge
```python
def set_challenge(
        body: str, 
        challenge: bytes
) -> str | dict:
    # <code>
    return '{"challenge": "C..."}'

# Function reference
SET_CHALLENGE = set_challenge
```
> [!NOTE]  
> The body is received as a string and can be returned as a string or json object (dict)