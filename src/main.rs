fn main() {
    println!("Hello, world!");

    // Just to create some coverage data, let's check if a specific file exists and print some other lines.
    let path = std::path::Path::new("src/main.rs");
    if path.exists() {
        println!("File exists!");
    } else {
        println!("File does not exist!");
    }
}

fn function1() {
    println!("Function 1");
}

fn function2() {
    println!("Function 2");
}

fn function3() {
    println!("Function 3");
}

// unit tests, fake
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function1() {
        function1();
    }

    #[test]
    fn test_function2() {
        function2();
    }

    #[test]
    fn test_function3() {
        function3();
    }
}
